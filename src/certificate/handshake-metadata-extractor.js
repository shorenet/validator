/**
 * TLS Handshake Metadata Extractor
 * Extracts SNI, TLS version, cipher suite, ALPN, and CertificateVerify from handshake data.
 *
 * Source locations:
 * - SNI: ClientHello (plaintext)
 * - TLS version: ServerHello (plaintext for announced, negotiated from record layer)
 * - Cipher suite: ServerHello (plaintext)
 * - ALPN: EncryptedExtensions (TLS 1.3, encrypted) or ServerHello extension (TLS 1.2)
 * - CertificateVerify: Encrypted handshake (TLS 1.3)
 *
 * Uses @peculiar/x509 + WebCrypto for browser compatibility.
 */

import { TLS_HANDSHAKE_TYPE } from './extractor.js';
import { base64ToBytes, hexToBytes, bytesToBase64 } from '../crypto/hash.js';

// Dynamic import for @peculiar/x509 to support both Node.js and browser
let x509Module = null;
let ed25519Module = null;

/**
 * Get the x509 module (lazy load)
 */
async function getX509() {
    if (x509Module) return x509Module;

    try {
        // Try npm package first (Node.js)
        x509Module = await import('@peculiar/x509');
    } catch {
        // Fall back to CDN for browser
        x509Module = await import('https://esm.sh/@peculiar/x509@1.9.7');
    }
    return x509Module;
}

/**
 * Get @noble/ed25519 module for Ed25519 verification (lazy load)
 */
async function getEd25519() {
    if (ed25519Module) return ed25519Module;

    try {
        // Try npm package first (Node.js)
        ed25519Module = await import('@noble/ed25519');
    } catch {
        // Fall back to CDN for browser
        ed25519Module = await import('https://esm.sh/@noble/ed25519@2.1.0');
    }
    return ed25519Module;
}

/**
 * TLS cipher suite names (common ones)
 */
const CIPHER_SUITES = {
    0x1301: 'TLS_AES_128_GCM_SHA256',
    0x1302: 'TLS_AES_256_GCM_SHA384',
    0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
    0x1304: 'TLS_AES_128_CCM_SHA256',
    0x1305: 'TLS_AES_128_CCM_8_SHA256',
    // TLS 1.2 common suites
    0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    0xcca8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    0xcca9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
};

/**
 * Signature algorithm names
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
 * Result structure for extracted metadata
 */
export class HandshakeMetadata {
    constructor() {
        this.sni = null;
        this.tlsVersion = null;
        this.cipherSuite = null;
        this.cipherSuiteCode = null;
        this.alpn = null;
        this.certificateVerify = null;  // TLS 1.3: { algorithm, algorithmCode, signature }
        this.serverKeyExchange = null;  // TLS 1.2: { algorithm, algorithmCode, signature }
        this.presentedTickets = [];     // Tickets from ClientHello pre_shared_key extension
        this.issuedTickets = [];        // Tickets from NewSessionTicket messages
    }

    /**
     * Get the handshake proof (signature) regardless of TLS version.
     * Returns CertificateVerify (TLS 1.3) or ServerKeyExchange signature (TLS 1.2).
     * @returns {{ algorithm: string, signature: string } | null}
     */
    getHandshakeProof() {
        if (this.certificateVerify) {
            return {
                algorithm: this.certificateVerify.algorithm,
                signature: this.certificateVerify.signature,
            };
        }
        if (this.serverKeyExchange) {
            return {
                algorithm: this.serverKeyExchange.algorithm,
                signature: this.serverKeyExchange.signature,
            };
        }
        return null;
    }
}

/**
 * Extract all available metadata from handshake data.
 *
 * @param {Array} handshakePlaintext - Array of {type, data, direction} from decrypted handshake
 * @param {Object} options - {verbose: boolean}
 * @returns {HandshakeMetadata}
 */
export function extractHandshakeMetadata(handshakePlaintext, options = {}) {
    const { verbose = false } = options;
    const metadata = new HandshakeMetadata();

    // Combine all handshake data by type
    for (const record of handshakePlaintext) {
        const data = record.data instanceof Uint8Array ? record.data : new Uint8Array(record.data);
        parseHandshakeMessages(data, metadata, verbose);
    }

    return metadata;
}

/**
 * Parse handshake messages from combined data.
 *
 * @param {Uint8Array} data - Combined handshake data
 * @param {HandshakeMetadata} metadata - Metadata object to populate
 * @param {boolean} verbose - Enable debug logging
 */
function parseHandshakeMessages(data, metadata, verbose) {
    let offset = 0;

    while (offset + 4 <= data.length) {
        const hsType = data[offset];
        const hsLen = (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];

        if (hsLen === 0 || offset + 4 + hsLen > data.length) {
            break;
        }

        const msgData = data.slice(offset + 4, offset + 4 + hsLen);

        switch (hsType) {
            case TLS_HANDSHAKE_TYPE.CLIENT_HELLO:
                parseClientHello(msgData, metadata, verbose);
                break;
            case TLS_HANDSHAKE_TYPE.SERVER_HELLO:
                parseServerHello(msgData, metadata, verbose);
                break;
            case TLS_HANDSHAKE_TYPE.SERVER_KEY_EXCHANGE:
                parseServerKeyExchange(msgData, metadata, verbose);
                break;
            case TLS_HANDSHAKE_TYPE.NEW_SESSION_TICKET:
                parseNewSessionTicket(msgData, metadata, verbose);
                break;
            case TLS_HANDSHAKE_TYPE.ENCRYPTED_EXTENSIONS:
                parseEncryptedExtensions(msgData, metadata, verbose);
                break;
            case TLS_HANDSHAKE_TYPE.CERTIFICATE_VERIFY:
                parseCertificateVerify(msgData, metadata, verbose);
                break;
        }

        offset += 4 + hsLen;
    }
}

/**
 * Parse ClientHello to extract SNI.
 *
 * ClientHello structure:
 * - legacy_version (2 bytes)
 * - random (32 bytes)
 * - legacy_session_id_length (1 byte)
 * - legacy_session_id (variable)
 * - cipher_suites_length (2 bytes)
 * - cipher_suites (variable)
 * - legacy_compression_methods_length (1 byte)
 * - legacy_compression_methods (variable)
 * - extensions_length (2 bytes)
 * - extensions (variable)
 *
 * SNI is in extension type 0 (server_name)
 */
function parseClientHello(data, metadata, verbose) {
    let offset = 0;

    // Skip legacy_version (2) + random (32)
    offset += 2 + 32;
    if (offset >= data.length) return;

    // Skip legacy_session_id
    const sessionIdLen = data[offset];
    offset += 1 + sessionIdLen;
    if (offset + 2 > data.length) return;

    // Skip cipher_suites
    const cipherSuitesLen = (data[offset] << 8) | data[offset + 1];
    offset += 2 + cipherSuitesLen;
    if (offset >= data.length) return;

    // Skip legacy_compression_methods
    const compLen = data[offset];
    offset += 1 + compLen;
    if (offset + 2 > data.length) return;

    // Parse extensions
    const extensionsLen = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    const extensionsEnd = offset + extensionsLen;

    while (offset + 4 <= extensionsEnd && offset + 4 <= data.length) {
        const extType = (data[offset] << 8) | data[offset + 1];
        const extLen = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;

        if (offset + extLen > data.length) break;

        // server_name extension (type 0)
        if (extType === 0x0000 && extLen >= 5) {
            const sni = parseServerNameExtension(data.slice(offset, offset + extLen));
            if (sni) {
                metadata.sni = sni;
                if (verbose) {
                    console.log(`  [META] Extracted SNI: ${sni}`);
                }
            }
        }

        // pre_shared_key extension (type 41 / 0x0029) - session resumption tickets
        if (extType === 0x0029 && extLen >= 2) {
            const tickets = parsePreSharedKeyExtension(data.slice(offset, offset + extLen));
            if (tickets.length > 0) {
                metadata.presentedTickets = tickets;
                if (verbose) {
                    console.log(`  [META] Extracted ${tickets.length} presented ticket(s) from ClientHello`);
                }
            }
        }

        offset += extLen;
    }
}

/**
 * Parse server_name extension to extract hostname.
 *
 * Structure:
 * - server_name_list_length (2 bytes)
 * - name_type (1 byte) - 0 for hostname
 * - name_length (2 bytes)
 * - name (variable)
 */
function parseServerNameExtension(data) {
    if (data.length < 5) return null;

    let offset = 0;
    const listLen = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    while (offset + 3 <= data.length && offset < 2 + listLen) {
        const nameType = data[offset];
        const nameLen = (data[offset + 1] << 8) | data[offset + 2];
        offset += 3;

        if (nameType === 0 && offset + nameLen <= data.length) {
            // hostname type
            return new TextDecoder().decode(data.slice(offset, offset + nameLen));
        }

        offset += nameLen;
    }

    return null;
}

/**
 * Parse ServerHello to extract TLS version and cipher suite.
 *
 * ServerHello structure:
 * - legacy_version (2 bytes) - always 0x0303 for TLS 1.3
 * - random (32 bytes)
 * - legacy_session_id_echo_length (1 byte)
 * - legacy_session_id_echo (variable)
 * - cipher_suite (2 bytes)
 * - legacy_compression_method (1 byte)
 * - extensions_length (2 bytes)
 * - extensions (variable)
 *
 * For TLS 1.3, actual version is in supported_versions extension (type 43)
 */
function parseServerHello(data, metadata, verbose) {
    let offset = 0;

    // Legacy version (2 bytes)
    if (offset + 2 > data.length) return;
    const legacyVersion = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    // Skip random (32 bytes)
    offset += 32;
    if (offset >= data.length) return;

    // Skip legacy_session_id_echo
    const sessionIdLen = data[offset];
    offset += 1 + sessionIdLen;
    if (offset + 2 > data.length) return;

    // Cipher suite (2 bytes)
    const cipherSuiteCode = (data[offset] << 8) | data[offset + 1];
    metadata.cipherSuiteCode = cipherSuiteCode;
    metadata.cipherSuite = CIPHER_SUITES[cipherSuiteCode] || `0x${cipherSuiteCode.toString(16).padStart(4, '0')}`;
    offset += 2;

    if (verbose) {
        console.log(`  [META] Extracted cipher suite: ${metadata.cipherSuite}`);
    }

    // Skip legacy_compression_method (1 byte)
    offset += 1;
    if (offset + 2 > data.length) {
        // No extensions, use legacy version
        metadata.tlsVersion = legacyVersion === 0x0303 ? 'TLS 1.2' : `0x${legacyVersion.toString(16)}`;
        return;
    }

    // Parse extensions
    const extensionsLen = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    const extensionsEnd = offset + extensionsLen;

    let foundVersion = false;
    while (offset + 4 <= extensionsEnd && offset + 4 <= data.length) {
        const extType = (data[offset] << 8) | data[offset + 1];
        const extLen = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;

        if (offset + extLen > data.length) break;

        // supported_versions extension (type 43)
        if (extType === 0x002b && extLen >= 2) {
            const version = (data[offset] << 8) | data[offset + 1];
            if (version === 0x0304) {
                metadata.tlsVersion = 'TLS 1.3';
            } else if (version === 0x0303) {
                metadata.tlsVersion = 'TLS 1.2';
            } else {
                metadata.tlsVersion = `0x${version.toString(16).padStart(4, '0')}`;
            }
            foundVersion = true;
            if (verbose) {
                console.log(`  [META] Extracted TLS version from extension: ${metadata.tlsVersion}`);
            }
        }

        // application_layer_protocol_negotiation extension (type 16) - TLS 1.2
        if (extType === 0x0010 && extLen >= 3) {
            const alpn = parseAlpnExtension(data.slice(offset, offset + extLen));
            if (alpn) {
                metadata.alpn = alpn;
                if (verbose) {
                    console.log(`  [META] Extracted ALPN from ServerHello: ${alpn}`);
                }
            }
        }

        offset += extLen;
    }

    if (!foundVersion) {
        // No supported_versions extension, use legacy version
        metadata.tlsVersion = legacyVersion === 0x0303 ? 'TLS 1.2' : `0x${legacyVersion.toString(16)}`;
        if (verbose) {
            console.log(`  [META] Using legacy TLS version: ${metadata.tlsVersion}`);
        }
    }
}

/**
 * Parse EncryptedExtensions to extract ALPN (TLS 1.3 only).
 *
 * EncryptedExtensions structure:
 * - extensions_length (2 bytes)
 * - extensions (variable)
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

        // application_layer_protocol_negotiation extension (type 16)
        if (extType === 0x0010 && extLen >= 3) {
            const alpn = parseAlpnExtension(data.slice(offset, offset + extLen));
            if (alpn) {
                metadata.alpn = alpn;
                if (verbose) {
                    console.log(`  [META] Extracted ALPN from EncryptedExtensions: ${alpn}`);
                }
            }
        }

        offset += extLen;
    }
}

/**
 * Parse ALPN extension.
 *
 * Structure:
 * - protocol_name_list_length (2 bytes)
 * - protocol_name_length (1 byte)
 * - protocol_name (variable)
 * - ... (more protocols)
 */
function parseAlpnExtension(data) {
    if (data.length < 3) return null;

    let offset = 0;
    const listLen = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    // Just get the first (selected) protocol
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
 *
 * CertificateVerify structure:
 * - algorithm (2 bytes)
 * - signature_length (2 bytes)
 * - signature (variable)
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
        console.log(`  [META] Extracted CertificateVerify: algorithm=${algorithm}, sigLen=${sigLen}`);
    }
}

/**
 * Parse ServerKeyExchange to extract signature algorithm, signature, and signed params (TLS 1.2 ECDHE).
 *
 * ServerKeyExchange structure for ECDHE:
 * - curve_type (1 byte) - 3 for named_curve
 * - named_curve (2 bytes) - e.g., 0x0017 for secp256r1
 * - public_key_length (1 byte)
 * - public_key (variable)
 * - signature_algorithm (2 bytes) - SignatureScheme
 * - signature_length (2 bytes)
 * - signature (variable)
 *
 * Note: This extracts the signature that proves server key ownership.
 * The server signs: client_random || server_random || server_params
 * Where server_params = curve_type || named_curve || public_key_length || public_key
 */
function parseServerKeyExchange(data, metadata, verbose) {
    if (data.length < 5) return;

    let offset = 0;

    // curve_type (1 byte)
    const curveType = data[offset];
    offset += 1;

    // For named_curve (type 3), parse curve id
    if (curveType === 3) {
        // named_curve (2 bytes)
        offset += 2;
        if (offset >= data.length) return;

        // public_key_length (1 byte)
        const pubKeyLen = data[offset];
        offset += 1;

        // Calculate where server_params ends (before signature)
        const serverParamsEnd = offset + pubKeyLen;

        // public_key (variable)
        offset += pubKeyLen;
        if (offset + 4 > data.length) return;

        // signature_algorithm (2 bytes)
        const algorithmCode = (data[offset] << 8) | data[offset + 1];
        offset += 2;

        // signature_length (2 bytes)
        const sigLen = (data[offset] << 8) | data[offset + 1];
        offset += 2;

        if (offset + sigLen > data.length) return;

        // signature (variable)
        const signature = data.slice(offset, offset + sigLen);
        const algorithm = SIGNATURE_ALGORITHMS[algorithmCode] || `0x${algorithmCode.toString(16).padStart(4, '0')}`;

        // Extract the server_params that are signed (curve_type || named_curve || public_key_length || public_key)
        const serverParams = data.slice(0, serverParamsEnd);

        metadata.serverKeyExchange = {
            algorithm,
            algorithmCode,
            signature: bytesToBase64(signature),
            serverParams: bytesToBase64(serverParams), // For verification
        };

        if (verbose) {
            console.log(`  [META] Extracted ServerKeyExchange: algorithm=${algorithm}, sigLen=${sigLen}, paramsLen=${serverParams.length}`);
        }
    } else {
        // Other key exchange types (RSA, DHE) have different structures
        // For now, we skip non-ECDHE key exchanges
        if (verbose) {
            console.log(`  [META] Skipping ServerKeyExchange with curve_type=${curveType} (not ECDHE named_curve)`);
        }
    }
}

/**
 * Extract metadata from raw TLS records (for cases where we have raw packets).
 *
 * @param {Array} packets - Array of {data, direction} packets
 * @param {Object} keylog - Parsed keylog for decryption
 * @param {Object} options - {verbose: boolean}
 * @returns {Promise<HandshakeMetadata>}
 */
export async function extractMetadataFromPackets(packets, keylog, options = {}) {
    const { verbose = false } = options;
    const metadata = new HandshakeMetadata();

    // For raw packets, we need to:
    // 1. Parse plaintext ClientHello/ServerHello
    // 2. Decrypt encrypted handshake for EncryptedExtensions/CertificateVerify

    for (const pkt of packets) {
        const data = typeof pkt.data === 'string' ? base64ToBytes(pkt.data) : pkt.data;
        if (!data || data.length < 5) continue;

        const contentType = data[0];

        // TLS Handshake record (plaintext)
        if (contentType === 0x16) {
            // Skip TLS record header (5 bytes)
            const recordData = data.slice(5);
            parseHandshakeMessages(recordData, metadata, verbose);
        }
    }

    return metadata;
}

/**
 * Parse pre_shared_key extension from ClientHello (RFC 8446 Section 4.2.11).
 * This contains the session tickets being presented for resumption.
 *
 * Structure:
 * - identities_length (2 bytes)
 * - For each identity:
 *   - identity_length (2 bytes)
 *   - identity (the ticket, variable)
 *   - obfuscated_ticket_age (4 bytes)
 * - binders_length (2 bytes)
 * - binders (variable, not needed for ticket extraction)
 *
 * @param {Uint8Array} data - pre_shared_key extension data
 * @returns {Uint8Array[]} Array of ticket bytes
 */
function parsePreSharedKeyExtension(data) {
    const tickets = [];
    if (data.length < 2) return tickets;

    let offset = 0;
    const identitiesLen = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    const identitiesEnd = offset + identitiesLen;

    while (offset + 2 <= identitiesEnd && offset + 2 <= data.length) {
        const identityLen = (data[offset] << 8) | data[offset + 1];
        offset += 2;

        if (offset + identityLen + 4 > data.length) break;

        // The identity is the session ticket
        const ticket = data.slice(offset, offset + identityLen);
        tickets.push(new Uint8Array(ticket));
        offset += identityLen;

        // Skip obfuscated_ticket_age (4 bytes)
        offset += 4;
    }

    return tickets;
}

/**
 * Parse NewSessionTicket message (RFC 8446 Section 4.6.1).
 * This is sent by the server to issue new session tickets.
 *
 * Structure:
 * - ticket_lifetime (4 bytes)
 * - ticket_age_add (4 bytes)
 * - ticket_nonce_length (1 byte)
 * - ticket_nonce (variable)
 * - ticket_length (2 bytes)
 * - ticket (variable)
 * - extensions_length (2 bytes)
 * - extensions (variable)
 *
 * @param {Uint8Array} data - NewSessionTicket message body
 * @param {HandshakeMetadata} metadata - Metadata object to populate
 * @param {boolean} verbose - Enable debug logging
 */
function parseNewSessionTicket(data, metadata, verbose) {
    if (data.length < 13) return;

    let offset = 0;

    // ticket_lifetime (4 bytes)
    offset += 4;

    // ticket_age_add (4 bytes)
    offset += 4;

    // ticket_nonce_length (1 byte)
    const nonceLen = data[offset];
    offset += 1;

    // ticket_nonce (variable)
    offset += nonceLen;
    if (offset + 2 > data.length) return;

    // ticket_length (2 bytes)
    const ticketLen = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    if (offset + ticketLen > data.length) return;

    // ticket (variable)
    const ticket = data.slice(offset, offset + ticketLen);
    metadata.issuedTickets.push(new Uint8Array(ticket));

    if (verbose) {
        console.log(`  [META] Extracted issued ticket: ${ticketLen} bytes`);
    }
}

/**
 * Compute SHA-256 hash of a ticket and return as hex string.
 *
 * @param {Uint8Array} ticket - Ticket bytes
 * @returns {Promise<string>} Hex-encoded SHA-256 hash
 */
export async function hashTicket(ticket) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', ticket);
    const hashArray = new Uint8Array(hashBuffer);
    return Array.from(hashArray).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Verify that a presented ticket matches one of the issued tickets.
 * Used to validate session resumption - the presented ticket hash must match
 * one of the issued ticket hashes from the original handshake.
 *
 * @param {Uint8Array[]} presentedTickets - Tickets from ClientHello pre_shared_key
 * @param {Uint8Array[]} issuedTickets - Tickets from NewSessionTicket messages
 * @param {Object} options - {verbose: boolean}
 * @returns {Promise<{valid: boolean, matchedHash: string|null, error: string|null}>}
 */
export async function verifyTicketLink(presentedTickets, issuedTickets, options = {}) {
    const { verbose = false } = options;

    if (!presentedTickets || presentedTickets.length === 0) {
        return { valid: false, matchedHash: null, error: 'No presented tickets' };
    }

    if (!issuedTickets || issuedTickets.length === 0) {
        return { valid: false, matchedHash: null, error: 'No issued tickets to compare' };
    }

    // Hash all issued tickets
    const issuedHashes = await Promise.all(issuedTickets.map(t => hashTicket(t)));

    if (verbose) {
        console.log(`  [TICKET] Issued ticket hashes: ${issuedHashes.map(h => h.slice(0, 16) + '...').join(', ')}`);
    }

    // Check if any presented ticket matches any issued ticket
    for (const presented of presentedTickets) {
        const presentedHash = await hashTicket(presented);

        if (verbose) {
            console.log(`  [TICKET] Checking presented ticket hash: ${presentedHash.slice(0, 16)}...`);
        }

        if (issuedHashes.includes(presentedHash)) {
            if (verbose) {
                console.log(`  [TICKET] Match found! Ticket verified.`);
            }
            return { valid: true, matchedHash: presentedHash, error: null };
        }
    }

    return { valid: false, matchedHash: null, error: 'No matching ticket found' };
}

/**
 * Verify the CertificateVerify signature using the certificate's public key.
 * Uses @peculiar/x509 + WebCrypto for browser compatibility.
 *
 * In TLS 1.3, the server signs:
 *   - 64 bytes of 0x20 (space)
 *   - "TLS 1.3, server CertificateVerify"
 *   - 0x00
 *   - transcript_hash (SHA-256 of handshake messages up to Certificate)
 *
 * @param {Object} certificateVerify - {algorithm, algorithmCode, signature (base64)}
 * @param {Uint8Array} transcriptHash - SHA-256 hash of handshake transcript
 * @param {string} certificateDer - Base64-encoded DER certificate (leaf cert)
 * @param {Object} options - {verbose: boolean}
 * @returns {Promise<{valid: boolean, error: string|null}>}
 */
export async function verifyCertificateVerifySignature(certificateVerify, transcriptHash, certificateDer, options = {}) {
    const { verbose = false } = options;

    if (!certificateVerify || !certificateVerify.signature) {
        return { valid: false, error: 'No CertificateVerify signature' };
    }

    // SHA-256 = 32 bytes, SHA-384 = 48 bytes
    if (!transcriptHash || (transcriptHash.length !== 32 && transcriptHash.length !== 48)) {
        return { valid: false, error: `Invalid transcript hash length: ${transcriptHash?.length || 0} (expected 32 or 48)` };
    }

    if (!certificateDer) {
        return { valid: false, error: 'No certificate for verification' };
    }

    try {
        const x509 = await getX509();

        // Build the signed content (RFC 8446 Section 4.4.3)
        // 64 spaces + context string + 0x00 + transcript hash
        const contextString = 'TLS 1.3, server CertificateVerify';
        const spaces = new Uint8Array(64).fill(0x20);
        const contextBytes = new TextEncoder().encode(contextString);
        const nullByte = new Uint8Array([0x00]);

        // Concatenate all parts
        const signedContent = new Uint8Array(64 + contextBytes.length + 1 + transcriptHash.length);
        signedContent.set(spaces, 0);
        signedContent.set(contextBytes, 64);
        signedContent.set(nullByte, 64 + contextBytes.length);
        signedContent.set(transcriptHash, 64 + contextBytes.length + 1);

        // Decode signature from base64
        const signature = base64ToBytes(certificateVerify.signature);

        // Parse certificate to get public key
        const certDer = base64ToBytes(certificateDer);
        const cert = new x509.X509Certificate(certDer);

        // Map algorithm code to WebCrypto algorithm
        const algorithmCode = certificateVerify.algorithmCode;
        let webCryptoAlgorithm;
        let importAlgorithm;

        switch (algorithmCode) {
            case 0x0401: // rsa_pkcs1_sha256
                webCryptoAlgorithm = { name: 'RSASSA-PKCS1-v1_5' };
                importAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
                break;
            case 0x0501: // rsa_pkcs1_sha384
                webCryptoAlgorithm = { name: 'RSASSA-PKCS1-v1_5' };
                importAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' };
                break;
            case 0x0601: // rsa_pkcs1_sha512
                webCryptoAlgorithm = { name: 'RSASSA-PKCS1-v1_5' };
                importAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' };
                break;
            case 0x0403: // ecdsa_secp256r1_sha256
                webCryptoAlgorithm = { name: 'ECDSA', hash: 'SHA-256' };
                importAlgorithm = { name: 'ECDSA', namedCurve: 'P-256' };
                break;
            case 0x0503: // ecdsa_secp384r1_sha384
                webCryptoAlgorithm = { name: 'ECDSA', hash: 'SHA-384' };
                importAlgorithm = { name: 'ECDSA', namedCurve: 'P-384' };
                break;
            case 0x0603: // ecdsa_secp521r1_sha512
                webCryptoAlgorithm = { name: 'ECDSA', hash: 'SHA-512' };
                importAlgorithm = { name: 'ECDSA', namedCurve: 'P-521' };
                break;
            case 0x0804: // rsa_pss_rsae_sha256
                webCryptoAlgorithm = { name: 'RSA-PSS', saltLength: 32 };
                importAlgorithm = { name: 'RSA-PSS', hash: 'SHA-256' };
                break;
            case 0x0805: // rsa_pss_rsae_sha384
                webCryptoAlgorithm = { name: 'RSA-PSS', saltLength: 48 };
                importAlgorithm = { name: 'RSA-PSS', hash: 'SHA-384' };
                break;
            case 0x0806: // rsa_pss_rsae_sha512
                webCryptoAlgorithm = { name: 'RSA-PSS', saltLength: 64 };
                importAlgorithm = { name: 'RSA-PSS', hash: 'SHA-512' };
                break;
            case 0x0807: // ed25519
                webCryptoAlgorithm = { name: 'Ed25519' };
                importAlgorithm = { name: 'Ed25519' };
                break;
            case 0x0808: // ed448
                webCryptoAlgorithm = { name: 'Ed448' };
                importAlgorithm = { name: 'Ed448' };
                break;
            default:
                return { valid: false, error: `Unsupported signature algorithm: 0x${algorithmCode.toString(16)}` };
        }

        if (verbose) {
            console.log(`  [VERIFY] Algorithm: ${certificateVerify.algorithm} (0x${algorithmCode.toString(16)})`);
            console.log(`  [VERIFY] Signature length: ${signature.length} bytes`);
            console.log(`  [VERIFY] Transcript hash length: ${transcriptHash.length} bytes`);
            console.log(`  [VERIFY] Signed content length: ${signedContent.length} bytes`);
        }

        let isValid;

        // Ed25519 uses @noble/ed25519 since WebCrypto support is inconsistent across browsers
        if (algorithmCode === 0x0807) { // Ed25519
            const ed = await getEd25519();
            // Extract raw public key from SPKI (skip ASN.1 header)
            // Ed25519 SPKI: 30 2a 30 05 06 03 2b 65 70 03 21 00 [32 bytes]
            const spkiBytes = new Uint8Array(cert.publicKey.rawData);
            const rawPubKey = spkiBytes.slice(-32); // Last 32 bytes are the key

            isValid = await ed.verifyAsync(signature, signedContent, rawPubKey);
        } else if (algorithmCode === 0x0808) { // Ed448
            // Ed448 is rare and not supported - return error
            return { valid: false, error: 'Ed448 not supported in browser (use Node.js)' };
        } else {
            // @peculiar/x509's export() accepts algorithm params to get correct key type
            // This is important for RSA-PSS vs RSASSA-PKCS1-v1_5
            const cryptoKey = await cert.publicKey.export(importAlgorithm, ['verify']);

            // For ECDSA, we may need to convert the signature from DER to raw format
            let signatureForVerify = signature;
            if (webCryptoAlgorithm.name === 'ECDSA') {
                // ECDSA signatures in TLS are DER-encoded, but WebCrypto expects raw (r || s)
                signatureForVerify = derSignatureToRaw(signature, algorithmCode);
            }

            // Verify signature using WebCrypto
            isValid = await crypto.subtle.verify(
                webCryptoAlgorithm,
                cryptoKey,
                signatureForVerify,
                signedContent
            );
        }

        if (verbose) {
            console.log(`  [VERIFY] Signature valid: ${isValid}`);
        }

        return { valid: isValid, error: isValid ? null : 'Signature verification failed' };
    } catch (e) {
        if (verbose) {
            console.log(`  [VERIFY] Error: ${e.message}`);
        }
        return { valid: false, error: e.message };
    }
}

/**
 * Convert a DER-encoded ECDSA signature to raw format (r || s).
 * WebCrypto expects raw format, but TLS uses DER encoding.
 *
 * @param {Uint8Array} derSig - DER-encoded signature
 * @param {number} algorithmCode - TLS signature algorithm code
 * @returns {Uint8Array} Raw signature (r || s)
 */
function derSignatureToRaw(derSig, algorithmCode) {
    // Determine the expected length of r and s based on curve
    let componentLength;
    switch (algorithmCode) {
        case 0x0403: // P-256
            componentLength = 32;
            break;
        case 0x0503: // P-384
            componentLength = 48;
            break;
        case 0x0603: // P-521
            componentLength = 66;
            break;
        default:
            // Unknown curve, return as-is
            return derSig;
    }

    try {
        // DER format: SEQUENCE { INTEGER r, INTEGER s }
        // 0x30 <len> 0x02 <r-len> <r-bytes> 0x02 <s-len> <s-bytes>
        if (derSig[0] !== 0x30) {
            // Not DER-encoded, might already be raw
            return derSig;
        }

        let offset = 2; // Skip SEQUENCE tag and length

        // Parse r
        if (derSig[offset] !== 0x02) return derSig;
        offset++;
        const rLen = derSig[offset];
        offset++;
        let r = derSig.slice(offset, offset + rLen);
        offset += rLen;

        // Parse s
        if (derSig[offset] !== 0x02) return derSig;
        offset++;
        const sLen = derSig[offset];
        offset++;
        let s = derSig.slice(offset, offset + sLen);

        // Remove leading zeros and pad to component length
        r = padOrTrimComponent(r, componentLength);
        s = padOrTrimComponent(s, componentLength);

        // Concatenate r and s
        const raw = new Uint8Array(componentLength * 2);
        raw.set(r, 0);
        raw.set(s, componentLength);
        return raw;
    } catch {
        // If parsing fails, return original
        return derSig;
    }
}

/**
 * Pad or trim a component to the expected length.
 */
function padOrTrimComponent(component, expectedLength) {
    // Remove leading zero if present (DER uses leading zero for positive numbers with high bit set)
    if (component.length > expectedLength && component[0] === 0) {
        component = component.slice(1);
    }

    // Pad with leading zeros if needed
    if (component.length < expectedLength) {
        const padded = new Uint8Array(expectedLength);
        padded.set(component, expectedLength - component.length);
        return padded;
    }

    return component;
}

/**
 * Verify the ServerKeyExchange signature for TLS 1.2 ECDHE.
 * Uses @peculiar/x509 + WebCrypto for browser compatibility.
 *
 * The server signs: client_random || server_random || server_params
 * Where server_params = curve_type || named_curve || public_key_length || public_key
 *
 * @param {Object} serverKeyExchange - {algorithm, algorithmCode, signature (base64), serverParams (base64)}
 * @param {string} clientRandomHex - Client random (32 bytes as hex string)
 * @param {string} serverRandomHex - Server random (32 bytes as hex string)
 * @param {string} certificateDer - Base64-encoded DER certificate (leaf cert)
 * @param {Object} options - {verbose: boolean}
 * @returns {Promise<{valid: boolean, error: string|null}>}
 */
export async function verifyServerKeyExchangeSignature(serverKeyExchange, clientRandomHex, serverRandomHex, certificateDer, options = {}) {
    const { verbose = false } = options;

    if (!serverKeyExchange || !serverKeyExchange.signature) {
        return { valid: false, error: 'No ServerKeyExchange signature' };
    }

    if (!serverKeyExchange.serverParams) {
        return { valid: false, error: 'No ServerKeyExchange server_params for verification' };
    }

    if (!clientRandomHex || clientRandomHex.length !== 64) {
        return { valid: false, error: `Invalid client_random length: ${clientRandomHex?.length || 0} hex chars (expected 64)` };
    }

    if (!serverRandomHex || serverRandomHex.length !== 64) {
        return { valid: false, error: `Invalid server_random length: ${serverRandomHex?.length || 0} hex chars (expected 64)` };
    }

    if (!certificateDer) {
        return { valid: false, error: 'No certificate for verification' };
    }

    try {
        const x509 = await getX509();

        // Build the signed content: client_random || server_random || server_params
        const clientRandom = hexToBytes(clientRandomHex);
        const serverRandom = hexToBytes(serverRandomHex);
        const serverParams = base64ToBytes(serverKeyExchange.serverParams);

        // Concatenate all parts
        const signedContent = new Uint8Array(clientRandom.length + serverRandom.length + serverParams.length);
        signedContent.set(clientRandom, 0);
        signedContent.set(serverRandom, clientRandom.length);
        signedContent.set(serverParams, clientRandom.length + serverRandom.length);

        // Decode signature from base64
        const signature = base64ToBytes(serverKeyExchange.signature);

        // Parse certificate to get public key
        const certDer = base64ToBytes(certificateDer);
        const cert = new x509.X509Certificate(certDer);

        // Map algorithm code to WebCrypto algorithm
        const algorithmCode = serverKeyExchange.algorithmCode;
        let webCryptoAlgorithm;
        let importAlgorithm;

        switch (algorithmCode) {
            case 0x0401: // rsa_pkcs1_sha256
                webCryptoAlgorithm = { name: 'RSASSA-PKCS1-v1_5' };
                importAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
                break;
            case 0x0501: // rsa_pkcs1_sha384
                webCryptoAlgorithm = { name: 'RSASSA-PKCS1-v1_5' };
                importAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' };
                break;
            case 0x0601: // rsa_pkcs1_sha512
                webCryptoAlgorithm = { name: 'RSASSA-PKCS1-v1_5' };
                importAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' };
                break;
            case 0x0403: // ecdsa_secp256r1_sha256
                webCryptoAlgorithm = { name: 'ECDSA', hash: 'SHA-256' };
                importAlgorithm = { name: 'ECDSA', namedCurve: 'P-256' };
                break;
            case 0x0503: // ecdsa_secp384r1_sha384
                webCryptoAlgorithm = { name: 'ECDSA', hash: 'SHA-384' };
                importAlgorithm = { name: 'ECDSA', namedCurve: 'P-384' };
                break;
            case 0x0603: // ecdsa_secp521r1_sha512
                webCryptoAlgorithm = { name: 'ECDSA', hash: 'SHA-512' };
                importAlgorithm = { name: 'ECDSA', namedCurve: 'P-521' };
                break;
            case 0x0804: // rsa_pss_rsae_sha256
                webCryptoAlgorithm = { name: 'RSA-PSS', saltLength: 32 };
                importAlgorithm = { name: 'RSA-PSS', hash: 'SHA-256' };
                break;
            case 0x0805: // rsa_pss_rsae_sha384
                webCryptoAlgorithm = { name: 'RSA-PSS', saltLength: 48 };
                importAlgorithm = { name: 'RSA-PSS', hash: 'SHA-384' };
                break;
            case 0x0806: // rsa_pss_rsae_sha512
                webCryptoAlgorithm = { name: 'RSA-PSS', saltLength: 64 };
                importAlgorithm = { name: 'RSA-PSS', hash: 'SHA-512' };
                break;
            default:
                return { valid: false, error: `Unsupported TLS 1.2 signature algorithm: 0x${algorithmCode.toString(16)}` };
        }

        if (verbose) {
            console.log(`  [VERIFY-SKE] Algorithm: ${serverKeyExchange.algorithm} (0x${algorithmCode.toString(16)})`);
            console.log(`  [VERIFY-SKE] Signature length: ${signature.length} bytes`);
            console.log(`  [VERIFY-SKE] Signed content: ${signedContent.length} bytes (32 + 32 + ${serverParams.length})`);
        }

        // @peculiar/x509's export() accepts algorithm params to get correct key type
        const cryptoKey = await cert.publicKey.export(importAlgorithm, ['verify']);

        // For ECDSA, we may need to convert the signature from DER to raw format
        let signatureForVerify = signature;
        if (webCryptoAlgorithm.name === 'ECDSA') {
            // ECDSA signatures in TLS are DER-encoded, but WebCrypto expects raw (r || s)
            signatureForVerify = derSignatureToRaw(signature, algorithmCode);
        }

        // Verify signature using WebCrypto
        const isValid = await crypto.subtle.verify(
            webCryptoAlgorithm,
            cryptoKey,
            signatureForVerify,
            signedContent
        );

        if (verbose) {
            console.log(`  [VERIFY-SKE] Signature valid: ${isValid}`);
        }

        return { valid: isValid, error: isValid ? null : 'ServerKeyExchange signature verification failed' };
    } catch (e) {
        if (verbose) {
            console.log(`  [VERIFY-SKE] Error: ${e.message}`);
        }
        return { valid: false, error: e.message };
    }
}

/**
 * Compute the transcript hash from handshake plaintext records.
 *
 * The transcript hash for CertificateVerify is SHA-256 (or SHA-384) of:
 * ClientHello || ServerHello || EncryptedExtensions || Certificate
 * (all including their 4-byte handshake message headers)
 *
 * @param {Array} handshakePlaintext - Array of {type, data, direction} records
 * @param {Object} options - {verbose: boolean, cipherSuite: string}
 * @returns {Promise<{hash: Uint8Array|null, error: string|null}>}
 */
export async function computeTranscriptHash(handshakePlaintext, options = {}) {
    const { verbose = false, cipherSuite = '' } = options;

    // Determine hash algorithm based on cipher suite
    // SHA-384 for *_SHA384 suites, SHA-256 for everything else
    const useSha384 = cipherSuite.includes('SHA384') || cipherSuite.includes('_384');

    if (!handshakePlaintext || handshakePlaintext.length === 0) {
        return { hash: null, error: 'No handshake plaintext' };
    }

    // Collect handshake messages in order
    // We need: ClientHello (1), ServerHello (2), EncryptedExtensions (8), Certificate (11)
    // Stop BEFORE CertificateVerify (15)
    //
    // IMPORTANT: In TLS 1.3, direction matters:
    // - ClientHello comes from client
    // - ServerHello, EncryptedExtensions, Certificate come from server
    // We must filter to avoid including misparses from wrong direction
    const transcriptMessages = [];
    const clientTypes = new Set([TLS_HANDSHAKE_TYPE.CLIENT_HELLO]);
    const serverTypes = new Set([
        TLS_HANDSHAKE_TYPE.SERVER_HELLO,
        TLS_HANDSHAKE_TYPE.ENCRYPTED_EXTENSIONS,
        TLS_HANDSHAKE_TYPE.CERTIFICATE,
        TLS_HANDSHAKE_TYPE.COMPRESSED_CERTIFICATE,
    ]);

    for (const record of handshakePlaintext) {
        const data = record.data instanceof Uint8Array ? record.data : new Uint8Array(record.data);
        const direction = record.direction; // 'client' or 'server'

        // Parse handshake messages from this record
        let offset = 0;
        while (offset + 4 <= data.length) {
            const hsType = data[offset];
            const hsLen = (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];

            if (hsLen === 0 || offset + 4 + hsLen > data.length) {
                break;
            }

            // Stop before CertificateVerify
            if (hsType === TLS_HANDSHAKE_TYPE.CERTIFICATE_VERIFY) {
                break;
            }

            // Include this message if it matches expected direction
            const isClientMsg = clientTypes.has(hsType) && direction === 'client';
            const isServerMsg = serverTypes.has(hsType) && direction === 'server';

            if (isClientMsg || isServerMsg) {
                // Include the full message with header
                const fullMessage = data.slice(offset, offset + 4 + hsLen);
                transcriptMessages.push({ type: hsType, data: fullMessage });

                if (verbose) {
                    const typeName = Object.entries(TLS_HANDSHAKE_TYPE).find(([_, v]) => v === hsType)?.[0] || `TYPE_${hsType}`;
                    console.log(`  [TRANSCRIPT] Including ${typeName} (${fullMessage.length} bytes) from ${direction}`);
                }
            }

            offset += 4 + hsLen;
        }
    }

    if (transcriptMessages.length === 0) {
        return { hash: null, error: 'No handshake messages found for transcript' };
    }

    // Concatenate all messages
    const totalLen = transcriptMessages.reduce((sum, m) => sum + m.data.length, 0);
    const transcript = new Uint8Array(totalLen);
    let pos = 0;
    for (const msg of transcriptMessages) {
        transcript.set(msg.data, pos);
        pos += msg.data.length;
    }

    // Compute hash (SHA-256 or SHA-384 based on cipher suite)
    const hashAlgo = useSha384 ? 'SHA-384' : 'SHA-256';
    if (verbose) {
        console.log(`  [TRANSCRIPT] Using ${hashAlgo} (cipher suite: ${cipherSuite})`);
    }
    const hashBuffer = await crypto.subtle.digest(hashAlgo, transcript);
    const hash = new Uint8Array(hashBuffer);

    if (verbose) {
        console.log(`  [TRANSCRIPT] Total: ${transcriptMessages.length} messages, ${totalLen} bytes`);
        console.log(`  [TRANSCRIPT] Hash: ${Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 32)}...`);
    }

    return { hash, error: null };
}
