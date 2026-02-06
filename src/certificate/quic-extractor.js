/**
 * QUIC certificate extraction from QUIC Handshake packets.
 * QUIC embeds TLS 1.3 inside CRYPTO frames in Handshake packets.
 */

import { findCertificateInHandshakeData, TLS_HANDSHAKE_TYPE } from './extractor.js';
import { QuicDecryptor, parseQuicFrames, splitCoalescedPackets, extractDcidFromInitial } from '../crypto/quic-decryptor.js';
import { base64ToBytes, bytesToBase64 } from '../crypto/hash.js';
import { HandshakeMetadata, verifyCertificateVerifySignature } from './handshake-metadata-extractor.js';

/**
 * Extract TLS/QUIC payload from raw packet data.
 *
 * Since framing is now stripped at capture time in the Rust pipeline,
 * packets are always transport payload (TLS records or QUIC packets).
 *
 * @param {Uint8Array} data - Raw packet bytes (already transport payload)
 * @returns {Uint8Array|null} The payload data, or null if empty
 */
function extractPayload(data) {
    if (!data || data.length === 0) return null;
    return data;
}

/**
 * Extract certificate chain and metadata from QUIC handshake packets.
 * QUIC embeds TLS 1.3 inside CRYPTO frames in Initial and Handshake packets.
 *
 * @param {Array} packets - Raw packets from forensic evidence
 * @param {Object} keys - Parsed keylog keys object (NOT full keylog, just keys)
 * @param {Object} options - Validation options {verbose: boolean}
 * @returns {Promise<{chain: string[]|null, metadata: HandshakeMetadata|null, error: string|null}>}
 */
export async function extractFromQuicHandshake(packets, keys, options = {}) {
    const { verbose = false } = options;

    if (verbose) {
        console.log(`  [QUIC-CERT] extractFromQuicHandshake called with ${packets?.length || 0} packets`);
        console.log(`  [QUIC-CERT] Keys available: client_hs=${!!keys.client_handshake_traffic_secret}, server_hs=${!!keys.server_handshake_traffic_secret}`);
    }

    // Check for handshake keys
    if (!keys.client_handshake_traffic_secret || !keys.server_handshake_traffic_secret) {
        return { chain: null, metadata: null, error: 'Missing QUIC handshake traffic secrets' };
    }

    // Split coalesced packets and categorize by type (Initial=0, Handshake=2)
    const allInitialPackets = [];
    const allHandshakePackets = [];
    let dcid = null;

    for (const p of packets) {
        // Support both 'data' and 'ciphertext' field names
        const rawBase64 = p.ciphertext || p.data;
        if (verbose && !rawBase64) {
            console.log(`  [QUIC-CERT] Packet missing data field, direction=${p.direction}`);
        }
        if (!rawBase64) continue;

        const raw = base64ToBytes(rawBase64);
        const payload = extractPayload(raw);
        if (!payload || payload.length === 0) {
            if (verbose) console.log(`  [QUIC-CERT] Empty payload for packet, direction=${p.direction}`);
            continue;
        }

        // Split coalesced packets and check each one
        const subPackets = splitCoalescedPackets(payload);
        if (verbose) {
            console.log(`  [QUIC-CERT] Packet ${p.direction}: ${payload.length} bytes -> ${subPackets.length} sub-packets, types=[${subPackets.map(s => s.type).join(',')}]`);
        }
        for (const subPkt of subPackets) {
            if (subPkt.type === 0) {
                // Initial packet
                allInitialPackets.push({
                    ...p,
                    _splitData: subPkt.data
                });
                // Extract DCID from first client Initial packet
                if (!dcid && p.direction === 'client_to_server') {
                    dcid = extractDcidFromInitial(subPkt.data);
                    if (verbose && dcid) {
                        console.log(`  [QUIC-CERT] Extracted DCID: ${Array.from(dcid).map(b => b.toString(16).padStart(2, '0')).join('')}`);
                    }
                }
            } else if (subPkt.type === 2) {
                // Handshake packet
                allHandshakePackets.push({
                    ...p,
                    _splitData: subPkt.data
                });
            }
        }
    }

    if (verbose) {
        console.log(`  [QUIC-CERT] Found ${allInitialPackets.length} Initial packets, ${allHandshakePackets.length} Handshake packets`);
    }

    if (allHandshakePackets.length === 0) {
        return { chain: null, metadata: null, error: 'No QUIC Handshake packets found (type=2)' };
    }

    // Initialize decryptor
    const decryptor = new QuicDecryptor();
    await decryptor.initialize({ keys });

    // Initialize Initial keys if we have DCID
    if (dcid) {
        await decryptor.initializeInitialKeys(dcid);
        if (verbose) {
            console.log(`  [QUIC-CERT] Initialized Initial keys from DCID`);
        }
    }

    // Collect CRYPTO frame data from Initial packets (ClientHello, ServerHello)
    const clientInitialCrypto = [];
    const serverInitialCrypto = [];

    for (const pkt of allInitialPackets) {
        const isServer = pkt.direction === 'server_to_client';
        const direction = isServer ? 'server' : 'client';

        const payload = pkt._splitData;
        if (!payload || payload.length === 0) continue;

        try {
            const decrypted = await decryptor.tryDecrypt(payload, direction);

            if (decrypted && decrypted.plaintext && decrypted.packetType === 'Initial') {
                const frames = parseQuicFrames(decrypted.plaintext);
                if (verbose) {
                    console.log(`  [QUIC-CERT] ${direction} Initial packet: ${frames.length} frames (${frames.filter(f => f.typeName === 'CRYPTO').length} CRYPTO)`);
                }
                for (const frame of frames) {
                    if (frame.typeName === 'CRYPTO') {
                        const target = isServer ? serverInitialCrypto : clientInitialCrypto;
                        target.push({
                            offset: frame.offset || 0,
                            data: frame.data
                        });
                        if (verbose) {
                            console.log(`    [CRYPTO] ${direction} Initial offset=${frame.offset}, len=${frame.data.length}`);
                        }
                    }
                }
            }
        } catch (e) {
            if (verbose) {
                console.log(`  [QUIC-CERT] Initial decrypt error (${direction}): ${e.message}`);
            }
        }
    }

    // Collect CRYPTO frame data from Handshake packets (EncryptedExtensions, Certificate, CertificateVerify)
    const serverHandshakeCrypto = [];

    for (const pkt of allHandshakePackets) {
        const isServer = pkt.direction === 'server_to_client';
        const direction = isServer ? 'server' : 'client';

        const payload = pkt._splitData;
        if (!payload || payload.length === 0) continue;

        try {
            const decrypted = await decryptor.tryDecrypt(payload, direction);

            if (verbose && isServer) {
                console.log(`  [QUIC-CERT] Server Handshake decrypt: payload=${payload.length}, decrypted=${decrypted ? 'yes' : 'no'}, type=${decrypted?.packetType || 'N/A'}`);
            }

            if (isServer && decrypted && decrypted.plaintext && decrypted.packetType === 'Handshake') {
                const frames = parseQuicFrames(decrypted.plaintext);
                if (verbose) {
                    console.log(`  [QUIC-CERT] Server Handshake packet: ${frames.length} frames (${frames.filter(f => f.typeName === 'CRYPTO').length} CRYPTO)`);
                }
                for (const frame of frames) {
                    if (frame.typeName === 'CRYPTO') {
                        serverHandshakeCrypto.push({
                            offset: frame.offset || 0,
                            data: frame.data
                        });
                        if (verbose) {
                            console.log(`    [CRYPTO] offset=${frame.offset}, len=${frame.data.length}`);
                        }
                    }
                }
            }
        } catch (e) {
            if (verbose) {
                console.log(`  [QUIC-CERT] Handshake decrypt error: ${e.message}`);
            }
        }
    }

    if (serverHandshakeCrypto.length === 0) {
        return { chain: null, metadata: null, error: 'No CRYPTO frames found in handshake' };
    }

    // Reassemble server Handshake CRYPTO data
    serverHandshakeCrypto.sort((a, b) => a.offset - b.offset);
    const totalLen = serverHandshakeCrypto.reduce((sum, f) => Math.max(sum, f.offset + f.data.length), 0);
    const serverHandshakeCryptoData = new Uint8Array(totalLen);
    for (const f of serverHandshakeCrypto) {
        serverHandshakeCryptoData.set(f.data, f.offset);
    }

    if (verbose) {
        console.log(`  [QUIC-CERT] Reassembled ${serverHandshakeCryptoData.length} bytes of server Handshake CRYPTO data`);
        // Log first 20 bytes to help debug parsing issues
        const hex = Array.from(serverHandshakeCryptoData.slice(0, 20)).map(b => b.toString(16).padStart(2, '0')).join(' ');
        console.log(`  [QUIC-CERT] First 20 bytes: ${hex}`);
    }

    // Parse TLS handshake messages from server Handshake CRYPTO data
    const certChain = findCertificateInHandshakeData(serverHandshakeCryptoData, verbose, true);

    if (verbose && !certChain) {
        console.log(`  [QUIC-CERT] findCertificateInHandshakeData returned null - no Certificate found in TLS messages`);
    }

    // Extract metadata from server Handshake CRYPTO data (ALPN from EncryptedExtensions, CertificateVerify)
    const metadata = extractMetadataFromCryptoData(serverHandshakeCryptoData, verbose);

    // QUIC always uses TLS 1.3
    if (metadata) {
        metadata.tlsVersion = 'TLS 1.3';
    }

    // Verify CertificateVerify signature if we have all the pieces
    let certificateVerifyResult = null;
    if (certChain && certChain.length > 0 && metadata?.certificateVerify) {
        // Build full transcript: ClientHello + ServerHello + EncryptedExtensions + Certificate
        const transcriptHash = await computeFullQuicTranscriptHash(
            clientInitialCrypto,
            serverInitialCrypto,
            serverHandshakeCryptoData,
            verbose
        );

        if (transcriptHash) {
            certificateVerifyResult = await verifyCertificateVerifySignature(
                metadata.certificateVerify,
                transcriptHash,
                certChain[0], // leaf certificate
                { verbose }
            );

            if (verbose) {
                console.log(`  [QUIC-VERIFY] CertificateVerify signature: ${certificateVerifyResult.valid ? 'VALID' : 'INVALID'}`);
                if (certificateVerifyResult.error) {
                    console.log(`  [QUIC-VERIFY] Error: ${certificateVerifyResult.error}`);
                }
            }
        } else if (verbose) {
            console.log(`  [QUIC-VERIFY] Could not compute transcript hash`);
        }
    }

    // Extract SNI from ClientHello
    let sni = null;
    if (clientInitialCrypto.length > 0) {
        const clientHelloData = reassembleCrypto(clientInitialCrypto);
        sni = extractSniFromClientHello(clientHelloData, verbose);
        if (sni && metadata) {
            metadata.sni = sni;
        }
    }

    if (certChain) {
        return { chain: certChain, metadata, certificateVerifyResult, sni, error: null };
    }

    return { chain: null, metadata, certificateVerifyResult, sni, error: 'No Certificate message found in QUIC handshake' };
}

/**
 * Signature algorithm names (same as in handshake-metadata-extractor.js)
 */
const SIGNATURE_ALGORITHMS = {
    0x0401: 'rsa_pkcs1_sha256',
    0x0501: 'rsa_pkcs1_sha384',
    0x0601: 'rsa_pkcs1_sha512',
    0x0403: 'ecdsa_secp256r1_sha256',
    0x0503: 'ecdsa_secp384r1_sha384',
    0x0603: 'ecdsa_secp521r1_sha512',
    0x0804: 'rsa_pss_rsae_sha256',
    0x0805: 'rsa_pss_rsae_sha384',
    0x0806: 'rsa_pss_rsae_sha512',
    0x0807: 'ed25519',
    0x0808: 'ed448',
};

/**
 * Extract metadata from reassembled CRYPTO data.
 * Parses EncryptedExtensions for ALPN and CertificateVerify for handshake proof.
 *
 * @param {Uint8Array} data - Reassembled CRYPTO data (TLS handshake messages)
 * @param {boolean} verbose - Enable debug logging
 * @returns {HandshakeMetadata|null}
 */
function extractMetadataFromCryptoData(data, verbose) {
    const metadata = new HandshakeMetadata();
    let offset = 0;

    while (offset + 4 <= data.length) {
        const hsType = data[offset];
        const hsLen = (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];

        if (hsLen === 0 || offset + 4 + hsLen > data.length) {
            break;
        }

        const msgData = data.slice(offset + 4, offset + 4 + hsLen);

        switch (hsType) {
            case TLS_HANDSHAKE_TYPE.ENCRYPTED_EXTENSIONS:
                parseEncryptedExtensions(msgData, metadata, verbose);
                break;
            case TLS_HANDSHAKE_TYPE.CERTIFICATE_VERIFY:
                parseCertificateVerify(msgData, metadata, verbose);
                break;
        }

        offset += 4 + hsLen;
    }

    return metadata;
}

/**
 * Parse EncryptedExtensions to extract ALPN.
 */
function parseEncryptedExtensions(data, metadata, verbose) {
    if (data.length < 2) return;

    let offset = 0;
    const extensionsLen = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    const extensionsEnd = offset + extensionsLen;

    while (offset + 4 <= extensionsEnd && offset + 4 <= data.length) {
        const extType = (data[offset] << 8) | data[offset + 1];
        const extLen = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;

        if (offset + extLen > data.length) break;

        // application_layer_protocol_negotiation extension (type 16 / 0x0010)
        if (extType === 0x0010 && extLen >= 3) {
            const alpn = parseAlpnExtension(data.slice(offset, offset + extLen));
            if (alpn) {
                metadata.alpn = alpn;
                if (verbose) {
                    console.log(`  [QUIC-META] Extracted ALPN: ${alpn}`);
                }
            }
        }

        offset += extLen;
    }
}

/**
 * Parse ALPN extension to get protocol name.
 */
function parseAlpnExtension(data) {
    if (data.length < 3) return null;

    let offset = 0;
    const listLen = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    // Get the first (selected) protocol
    if (offset < data.length) {
        const protoLen = data[offset];
        offset += 1;
        if (offset + protoLen <= data.length) {
            return new TextDecoder().decode(data.slice(offset, offset + protoLen));
        }
    }

    return null;
}

/**
 * Parse CertificateVerify to extract signature algorithm and signature.
 */
function parseCertificateVerify(data, metadata, verbose) {
    if (data.length < 4) return;

    const algorithmCode = (data[0] << 8) | data[1];
    const sigLen = (data[2] << 8) | data[3];

    if (4 + sigLen > data.length) return;

    const signature = data.slice(4, 4 + sigLen);
    const algorithm = SIGNATURE_ALGORITHMS[algorithmCode] || `0x${algorithmCode.toString(16).padStart(4, '0')}`;

    metadata.certificateVerify = {
        algorithm,
        algorithmCode,
        signature: bytesToBase64(signature),
    };

    if (verbose) {
        console.log(`  [QUIC-META] Extracted CertificateVerify: algorithm=${algorithm}, sigLen=${sigLen}`);
    }
}

/**
 * Reassemble CRYPTO fragments into contiguous data.
 *
 * @param {Array<{offset: number, data: Uint8Array}>} fragments - CRYPTO fragments
 * @returns {Uint8Array} Reassembled data
 */
function reassembleCrypto(fragments) {
    if (fragments.length === 0) return new Uint8Array(0);

    fragments.sort((a, b) => a.offset - b.offset);
    const totalLen = fragments.reduce((sum, f) => Math.max(sum, f.offset + f.data.length), 0);
    const data = new Uint8Array(totalLen);
    for (const f of fragments) {
        data.set(f.data, f.offset);
    }
    return data;
}

/**
 * Extract SNI from ClientHello data.
 * ClientHello format:
 *   - Handshake header: type(1) + length(3)
 *   - Version (2 bytes)
 *   - Random (32 bytes)
 *   - Session ID length (1 byte) + Session ID (variable)
 *   - Cipher Suites length (2 bytes) + Cipher Suites (variable)
 *   - Compression Methods length (1 byte) + Compression Methods (variable)
 *   - Extensions length (2 bytes) + Extensions (variable)
 *
 * @param {Uint8Array} data - Reassembled CRYPTO data containing ClientHello
 * @param {boolean} verbose - Enable debug logging
 * @returns {string|null} - SNI hostname or null
 */
function extractSniFromClientHello(data, verbose) {
    if (!data || data.length < 43) return null; // Minimum ClientHello size

    // Check for ClientHello handshake type
    if (data[0] !== TLS_HANDSHAKE_TYPE.CLIENT_HELLO) {
        if (verbose) console.log(`  [QUIC-SNI] Not a ClientHello (type=${data[0]})`);
        return null;
    }

    // Get handshake length
    const hsLen = (data[1] << 16) | (data[2] << 8) | data[3];
    if (4 + hsLen > data.length) {
        if (verbose) console.log(`  [QUIC-SNI] ClientHello truncated`);
        return null;
    }

    let offset = 4; // Skip handshake header

    // Skip version (2 bytes)
    offset += 2;

    // Skip random (32 bytes)
    offset += 32;

    // Skip session ID
    if (offset >= data.length) return null;
    const sessionIdLen = data[offset];
    offset += 1 + sessionIdLen;

    // Skip cipher suites
    if (offset + 2 > data.length) return null;
    const cipherSuitesLen = (data[offset] << 8) | data[offset + 1];
    offset += 2 + cipherSuitesLen;

    // Skip compression methods
    if (offset >= data.length) return null;
    const compressionLen = data[offset];
    offset += 1 + compressionLen;

    // Extensions length
    if (offset + 2 > data.length) return null;
    const extensionsLen = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    const extensionsEnd = offset + extensionsLen;
    if (extensionsEnd > data.length) return null;

    // Parse extensions to find SNI (type 0)
    while (offset + 4 <= extensionsEnd) {
        const extType = (data[offset] << 8) | data[offset + 1];
        const extLen = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;

        if (extType === 0 && extLen > 0) {
            // SNI extension found
            // SNI format: list length (2) + name type (1) + name length (2) + name
            if (offset + 5 > extensionsEnd) return null;

            // Skip list length
            offset += 2;

            const nameType = data[offset];
            if (nameType !== 0) {
                // Not a DNS hostname
                offset += extLen - 2;
                continue;
            }
            offset += 1;

            const nameLen = (data[offset] << 8) | data[offset + 1];
            offset += 2;

            if (offset + nameLen > extensionsEnd) return null;

            const sni = new TextDecoder().decode(data.slice(offset, offset + nameLen));
            if (verbose) console.log(`  [QUIC-SNI] Extracted SNI: ${sni}`);
            return sni;
        }

        offset += extLen;
    }

    if (verbose) console.log(`  [QUIC-SNI] No SNI extension found`);
    return null;
}

/**
 * Extract TLS handshake messages from CRYPTO data.
 *
 * @param {Uint8Array} cryptoData - Reassembled CRYPTO data
 * @param {Set<number>} targetTypes - Handshake types to extract
 * @param {number|null} stopBeforeType - Stop when this type is encountered
 * @param {boolean} verbose - Enable debug logging
 * @returns {Array<Uint8Array>} Extracted handshake messages
 */
function extractHandshakeMessages(cryptoData, targetTypes, stopBeforeType, verbose) {
    const messages = [];
    let offset = 0;

    while (offset + 4 <= cryptoData.length) {
        const hsType = cryptoData[offset];
        const hsLen = (cryptoData[offset + 1] << 16) | (cryptoData[offset + 2] << 8) | cryptoData[offset + 3];

        if (hsLen === 0 || offset + 4 + hsLen > cryptoData.length) {
            break;
        }

        // Stop before specified type
        if (stopBeforeType !== null && hsType === stopBeforeType) {
            break;
        }

        // Include message if it matches target types
        if (targetTypes.has(hsType)) {
            const fullMessage = cryptoData.slice(offset, offset + 4 + hsLen);
            messages.push(fullMessage);

            if (verbose) {
                const typeName = getHandshakeTypeName(hsType);
                console.log(`  [QUIC-TRANSCRIPT] Including ${typeName} (${fullMessage.length} bytes)`);
            }
        }

        offset += 4 + hsLen;
    }

    return messages;
}

/**
 * Get human-readable name for TLS handshake type.
 */
function getHandshakeTypeName(hsType) {
    switch (hsType) {
        case TLS_HANDSHAKE_TYPE.CLIENT_HELLO: return 'ClientHello';
        case TLS_HANDSHAKE_TYPE.SERVER_HELLO: return 'ServerHello';
        case TLS_HANDSHAKE_TYPE.ENCRYPTED_EXTENSIONS: return 'EncryptedExtensions';
        case TLS_HANDSHAKE_TYPE.CERTIFICATE: return 'Certificate';
        case TLS_HANDSHAKE_TYPE.COMPRESSED_CERTIFICATE: return 'CompressedCertificate';
        case TLS_HANDSHAKE_TYPE.CERTIFICATE_VERIFY: return 'CertificateVerify';
        case TLS_HANDSHAKE_TYPE.FINISHED: return 'Finished';
        default: return `TYPE_${hsType}`;
    }
}

/**
 * Compute full QUIC transcript hash for CertificateVerify verification.
 *
 * The TLS 1.3 transcript includes (in order):
 * 1. ClientHello (from client Initial CRYPTO)
 * 2. ServerHello (from server Initial CRYPTO)
 * 3. EncryptedExtensions (from server Handshake CRYPTO)
 * 4. Certificate or CompressedCertificate (from server Handshake CRYPTO)
 *
 * @param {Array<{offset: number, data: Uint8Array}>} clientInitialCrypto - Client Initial CRYPTO fragments
 * @param {Array<{offset: number, data: Uint8Array}>} serverInitialCrypto - Server Initial CRYPTO fragments
 * @param {Uint8Array} serverHandshakeCryptoData - Reassembled server Handshake CRYPTO data
 * @param {boolean} verbose - Enable debug logging
 * @returns {Promise<Uint8Array|null>} SHA-256 hash of transcript, or null on failure
 */
async function computeFullQuicTranscriptHash(clientInitialCrypto, serverInitialCrypto, serverHandshakeCryptoData, verbose) {
    const transcriptMessages = [];

    // 1. Extract ClientHello from client Initial CRYPTO
    const clientInitialData = reassembleCrypto(clientInitialCrypto);
    if (clientInitialData.length > 0) {
        const clientHelloMessages = extractHandshakeMessages(
            clientInitialData,
            new Set([TLS_HANDSHAKE_TYPE.CLIENT_HELLO]),
            null,
            verbose
        );
        transcriptMessages.push(...clientHelloMessages);
    }

    // 2. Extract ServerHello from server Initial CRYPTO
    const serverInitialData = reassembleCrypto(serverInitialCrypto);
    if (serverInitialData.length > 0) {
        const serverHelloMessages = extractHandshakeMessages(
            serverInitialData,
            new Set([TLS_HANDSHAKE_TYPE.SERVER_HELLO]),
            null,
            verbose
        );
        transcriptMessages.push(...serverHelloMessages);
    }

    // 3 & 4. Extract EncryptedExtensions and Certificate from server Handshake CRYPTO
    const handshakeMessages = extractHandshakeMessages(
        serverHandshakeCryptoData,
        new Set([
            TLS_HANDSHAKE_TYPE.ENCRYPTED_EXTENSIONS,
            TLS_HANDSHAKE_TYPE.CERTIFICATE,
            TLS_HANDSHAKE_TYPE.COMPRESSED_CERTIFICATE,
        ]),
        TLS_HANDSHAKE_TYPE.CERTIFICATE_VERIFY, // Stop before CertificateVerify
        verbose
    );
    transcriptMessages.push(...handshakeMessages);

    if (verbose) {
        console.log(`  [QUIC-TRANSCRIPT] Full transcript: ${transcriptMessages.length} messages`);
        console.log(`  [QUIC-TRANSCRIPT] ClientHello: ${clientInitialCrypto.length > 0 ? 'found' : 'MISSING'}`);
        console.log(`  [QUIC-TRANSCRIPT] ServerHello: ${serverInitialCrypto.length > 0 ? 'found' : 'MISSING'}`);
    }

    // Require at least ClientHello, ServerHello, EncryptedExtensions, Certificate
    if (transcriptMessages.length < 4) {
        if (verbose) {
            console.log(`  [QUIC-TRANSCRIPT] Incomplete transcript: only ${transcriptMessages.length} messages (need 4)`);
        }
        return null;
    }

    // Concatenate all messages
    const totalLen = transcriptMessages.reduce((sum, m) => sum + m.length, 0);
    const transcript = new Uint8Array(totalLen);
    let pos = 0;
    for (const msg of transcriptMessages) {
        transcript.set(msg, pos);
        pos += msg.length;
    }

    // Compute SHA-256 hash (TLS 1.3 default for most cipher suites)
    const hashBuffer = await crypto.subtle.digest('SHA-256', transcript);
    const hash = new Uint8Array(hashBuffer);

    if (verbose) {
        console.log(`  [QUIC-TRANSCRIPT] Total: ${totalLen} bytes`);
        console.log(`  [QUIC-TRANSCRIPT] Hash: ${Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 32)}...`);
    }

    return hash;
}

/**
 * Compute transcript hash from QUIC CRYPTO data for CertificateVerify verification.
 * (Legacy version that only includes Handshake data - kept for backward compatibility)
 *
 * @param {Uint8Array} cryptoData - Reassembled CRYPTO data from server
 * @param {boolean} verbose - Enable debug logging
 * @returns {Promise<Uint8Array|null>} SHA-256 hash of transcript, or null on failure
 */
async function computeQuicTranscriptHash(cryptoData, verbose) {
    const messages = extractHandshakeMessages(
        cryptoData,
        new Set([
            TLS_HANDSHAKE_TYPE.ENCRYPTED_EXTENSIONS,
            TLS_HANDSHAKE_TYPE.CERTIFICATE,
            TLS_HANDSHAKE_TYPE.COMPRESSED_CERTIFICATE,
        ]),
        TLS_HANDSHAKE_TYPE.CERTIFICATE_VERIFY,
        verbose
    );

    if (messages.length === 0) {
        if (verbose) {
            console.log(`  [QUIC-TRANSCRIPT] No messages found for transcript`);
        }
        return null;
    }

    // Concatenate all messages
    const totalLen = messages.reduce((sum, m) => sum + m.length, 0);
    const transcript = new Uint8Array(totalLen);
    let pos = 0;
    for (const msg of messages) {
        transcript.set(msg, pos);
        pos += msg.length;
    }

    // Compute SHA-256 hash (TLS 1.3 default for most cipher suites)
    const hashBuffer = await crypto.subtle.digest('SHA-256', transcript);
    const hash = new Uint8Array(hashBuffer);

    if (verbose) {
        console.log(`  [QUIC-TRANSCRIPT] Total: ${messages.length} messages, ${totalLen} bytes`);
        console.log(`  [QUIC-TRANSCRIPT] Hash: ${Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 32)}...`);
    }

    return hash;
}
