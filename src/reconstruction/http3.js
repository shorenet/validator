/**
 * HTTP/3 Transaction Reconstructor
 * Reconstructs HTTP/3 transactions from decrypted QUIC frames
 *
 * Uses @peculiar/x509 + WebCrypto for browser compatibility.
 */

import { QuicDecryptor, parseQuicFrames } from '../crypto/quic-decryptor.js';
import { QpackDecoder } from '../protocol/http3/qpack-decoder.js';
import { buildNormalizedTransaction } from './shared.js';
import { base64ToBytes, toBytes } from '../encoding/bytes.js';
import { extractTlsPayload } from '../utils/payload.js';
import { extractFromQuicHandshake } from '../certificate/quic-extractor.js';
import { validateOriginalHandshake } from '../certificate/tls-extractor.js';

export class Http3Reconstructor {
    constructor(options = {}) {
        this.options = options;
    }

    /**
     * Reconstruct HTTP/3 transaction from decrypted QUIC stream data
     * @param {Object} claimed - Claimed transaction data (for identity fields)
     * @param {Object} evidence - Forensic evidence (keylog, quic_packets, etc.)
     * @returns {{reconstructed: Object|null, error: string|null, streamData: Object|null}}
     */
    async reconstruct(claimed, evidence) {
        const { verbose = false } = this.options;
        console.log(`[HTTP3] reconstruct() called, verbose=${verbose}, options=`, this.options);

        // Get stream ID
        const streamId = evidence.stream_id;
        if (streamId === undefined || streamId === null) {
            return { reconstructed: null, error: 'Missing stream_id', streamData: null };
        }

        // Get encoder streams and raw headers frames
        const clientEncoderStream = evidence.client_encoder_stream;
        const serverEncoderStream = evidence.server_encoder_stream;
        const requestHeadersFrame = evidence.request_headers_frame;
        const responseHeadersFrame = evidence.response_headers_frame;

        // Parse QUIC keylog
        const keylogLines = evidence.keylog?.split('\n').filter(l => l.trim()) || [];
        const keys = {};
        for (const line of keylogLines) {
            const parts = line.trim().split(/\s+/);
            if (parts.length < 3) continue;
            const label = parts[0].toLowerCase();
            keys[label] = parts[2];
        }

        if (!keys.client_traffic_secret_0) {
            return { reconstructed: null, error: 'Missing QUIC client traffic secret', streamData: null };
        }

        // Collect QUIC packets
        const hasNewFormat = evidence.quic_packets && evidence.quic_packets.length > 0;
        const packets = [];

        if (hasNewFormat) {
            // NEW ARCHITECTURE: Direct QUIC packet evidence
            for (const pkt of evidence.quic_packets) {
                const data = base64ToBytes(pkt.ciphertext);
                if (data && data.length > 0) {
                    packets.push({
                        direction: pkt.direction,
                        data: data,
                        packetNumber: pkt.packet_number,
                        encryptionLevel: pkt.encryption_level
                    });
                }
            }
        } else {
            // LEGACY ARCHITECTURE: Extract from raw_packets
            for (const pkt of evidence.raw_packets?.packets || []) {
                const data = base64ToBytes(pkt.data);
                const payload = extractTlsPayload(data);
                if (payload && payload.length > 0) {
                    packets.push({ direction: pkt.direction, data: payload });
                }
            }
        }

        if (packets.length === 0) {
            return { reconstructed: null, error: 'No QUIC packets', streamData: null };
        }

        // Sort packets by packet number for correct PN reconstruction
        packets.sort((a, b) => {
            if (a.packetNumber !== undefined && b.packetNumber !== undefined) {
                return a.packetNumber - b.packetNumber;
            }
            return a.direction.localeCompare(b.direction);
        });

        // Initialize QuicDecryptor
        const decryptor = new QuicDecryptor();
        try {
            await decryptor.initialize({ keys });
        } catch (e) {
            if (verbose) console.log(`  QUIC init error: ${e.message}`);
            return { reconstructed: null, error: `QUIC key derivation failed: ${e.message}`, streamData: null };
        }

        // Pre-seed packet number state from known packet numbers (for new format)
        if (hasNewFormat) {
            let minClientPn = Infinity;
            let minServerPn = Infinity;
            for (const pkt of packets) {
                if (pkt.packetNumber !== undefined && pkt.encryptionLevel === 3) {
                    if (pkt.direction === 'client_to_server') {
                        minClientPn = Math.min(minClientPn, pkt.packetNumber);
                    } else {
                        minServerPn = Math.min(minServerPn, pkt.packetNumber);
                    }
                }
            }
            if (minClientPn !== Infinity) {
                decryptor.largestClientPn = minClientPn - 1;
                if (verbose) console.log(`  Seeded client PN state: ${decryptor.largestClientPn}`);
            }
            if (minServerPn !== Infinity) {
                decryptor.largestServerPn = minServerPn - 1;
                if (verbose) console.log(`  Seeded server PN state: ${decryptor.largestServerPn}`);
            }
        }

        // Decrypt all packets and collect STREAM frames by stream ID
        const streamData = { client: new Map(), server: new Map() };
        let decryptedAny = false;

        for (const pkt of packets) {
            const direction = pkt.direction === 'client_to_server' ? 'client' : 'server';

            try {
                const decrypted = await decryptor.tryDecrypt(pkt.data, direction);
                if (decrypted && decrypted.plaintext && decrypted.plaintext.length > 0) {
                    decryptedAny = true;

                    // Parse QUIC frames to extract STREAM data
                    try {
                        const frames = parseQuicFrames(decrypted.plaintext);
                        for (const frame of frames) {
                            if (frame.typeName === 'STREAM' && frame.streamId === streamId) {
                                const dirMap = streamData[direction];
                                if (!dirMap.has(frame.streamId)) {
                                    dirMap.set(frame.streamId, []);
                                }
                                dirMap.get(frame.streamId).push({
                                    offset: frame.offset || 0,
                                    data: frame.data
                                });
                            }
                        }
                    } catch (e) {
                        if (verbose) console.log(`  QUIC frame parse error: ${e.message}`);
                    }
                }
            } catch (e) {
                if (verbose) console.log(`  QUIC decrypt error: ${e.message}`);
            }
        }

        if (!decryptedAny) {
            return { reconstructed: null, error: 'QUIC decryption failed - no packets could be decrypted', streamData: null };
        }

        // Decode headers using encoder stream approach
        let parsedRequest = null;
        let parsedResponse = null;

        const requestBytes = requestHeadersFrame ? toBytes(requestHeadersFrame) : null;
        const responseBytes = responseHeadersFrame ? toBytes(responseHeadersFrame) : null;

        const requestRicZero = requestBytes && requestBytes.length > 0 && requestBytes[0] === 0;
        const responseRicZero = responseBytes && responseBytes.length > 0 && responseBytes[0] === 0;

        // Can decode if we have headers AND (encoder stream OR RIC=0)
        const canDecodeRequest = requestHeadersFrame && requestHeadersFrame.length > 0 &&
            (requestRicZero || (clientEncoderStream && clientEncoderStream.length > 0));
        const canDecodeResponse = responseHeadersFrame && responseHeadersFrame.length > 0 &&
            (responseRicZero || (serverEncoderStream && serverEncoderStream.length > 0));
        const useEncoderStreamApproach = canDecodeRequest && canDecodeResponse;

        if (useEncoderStreamApproach) {
            // Initialize request decoder from client encoder stream
            const requestQpack = new QpackDecoder(4096);
            if (clientEncoderStream && clientEncoderStream.length > 0) {
                try {
                    const encoderData = toBytes(clientEncoderStream);
                    requestQpack.processEncoderStream(encoderData);
                    if (verbose) console.log(`  Processed client encoder stream: ${encoderData.length} bytes, KRC=${requestQpack.knownReceivedCount}`);
                } catch (e) {
                    if (verbose) console.log(`  Client encoder stream error: ${e.message}`);
                }
            }

            // Initialize response decoder from server encoder stream
            const responseQpack = new QpackDecoder(4096);
            if (serverEncoderStream && serverEncoderStream.length > 0) {
                try {
                    const encoderData = toBytes(serverEncoderStream);
                    responseQpack.processEncoderStream(encoderData);
                    if (verbose) console.log(`  Processed server encoder stream: ${encoderData.length} bytes, KRC=${responseQpack.knownReceivedCount}`);
                } catch (e) {
                    if (verbose) console.log(`  Server encoder stream error: ${e.message}`);
                }
            }

            // Decode request headers
            if (canDecodeRequest) {
                try {
                    const headerBytes = toBytes(requestHeadersFrame);
                    const headers = requestQpack.decode(headerBytes, true);
                    const headerMap = {};
                    for (const [name, value] of headers) {
                        headerMap[name] = value;
                    }
                    parsedRequest = {
                        method: headerMap[':method'],
                        path: headerMap[':path'],
                        authority: headerMap[':authority'],
                        scheme: headerMap[':scheme'],
                        headers: headerMap
                    };
                    if (verbose) console.log(`  Decoded request: ${parsedRequest.method} ${parsedRequest.path}`);
                } catch (e) {
                    if (verbose) console.log(`  Request HEADERS decode error: ${e.message}`);
                }
            }

            // Decode response headers
            if (canDecodeResponse) {
                try {
                    const headerBytes = toBytes(responseHeadersFrame);
                    const headers = responseQpack.decode(headerBytes, true);
                    const headerMap = {};
                    for (const [name, value] of headers) {
                        headerMap[name] = value;
                    }
                    parsedResponse = {
                        status: parseInt(headerMap[':status'], 10),
                        headers: headerMap
                    };
                    if (verbose) console.log(`  Decoded response: ${parsedResponse.status}`);
                } catch (e) {
                    if (verbose) console.log(`  Response HEADERS decode error: ${e.message}`);
                }
            }
        } else {
            if (verbose) {
                const reqByte0 = requestHeadersFrame?.[0];
                const resByte0 = responseHeadersFrame?.[0];
                console.log(`  Cannot decode headers:`);
                console.log(`    Request: headers=${requestHeadersFrame?.length || 0}, RIC byte=${reqByte0}, encoder=${clientEncoderStream?.length || 0}`);
                console.log(`    Response: headers=${responseHeadersFrame?.length || 0}, RIC byte=${resByte0}, encoder=${serverEncoderStream?.length || 0}`);
            }
            return { reconstructed: null, error: 'Cannot decode headers - missing encoder streams or RIC > 0', streamData };
        }

        if (!parsedRequest) {
            return { reconstructed: null, error: 'Failed to parse request headers', streamData };
        }

        // Extract certificates from QUIC handshake packets (independent verification)
        // Filter for handshake-level packets (encryption_level 0=Initial, 2=Handshake)
        // Always log this to help debug browser issues
        console.log(`[HTTP3] Certificate extraction starting, verbose=${verbose}, quic_packets=${evidence.quic_packets?.length || 0}`);
        if (verbose) {
            console.log(`  [CERT] quic_packets available: ${evidence.quic_packets?.length || 0}`);
            if (evidence.quic_packets?.length > 0) {
                console.log(`  [CERT] First 3 packets encryption_levels: ${evidence.quic_packets.slice(0, 3).map(p => p.encryption_level).join(', ')}`);
            }
        }

        const handshakePackets = (evidence.quic_packets || [])
            .filter(p => p.encryption_level === 0 || p.encryption_level === 2)
            .map(p => ({
                direction: p.direction,
                data: p.ciphertext  // Already base64 encoded
            }));

        if (verbose) {
            console.log(`  [CERT] Found ${handshakePackets.length} handshake packets for cert extraction (encryption_level 0 or 2)`);
            if (handshakePackets.length > 0) {
                console.log(`  [CERT] First packet: direction=${handshakePackets[0].direction}, data.length=${handshakePackets[0].data?.length || 0}`);
            }
        }

        let extractedCerts = await this.extractFromQuicHandshake(handshakePackets, keys);
        let extractedMetadata = extractedCerts.metadata;
        let certificateVerifyResult = extractedCerts.certificateVerifyResult || null;
        // Preserve SNI from current session's ClientHello (even if we use original_handshake certs)
        const extractedSni = extractedCerts.sni;

        // If direct extraction failed, try original_handshake for resumed sessions
        if (!extractedCerts.chain && evidence.original_handshake) {
            if (verbose) {
                console.log(`  [CERT] Direct extraction failed, trying original_handshake`);
            }
            // For resumed sessions, use certificates from original handshake
            if (evidence.original_handshake.certificate_chain?.length > 0) {
                extractedCerts = {
                    chain: evidence.original_handshake.certificate_chain,
                    metadata: null,
                    certificateVerifyResult: null,
                    sni: extractedSni, // Preserve SNI from current session
                    error: null
                };
                if (verbose) {
                    console.log(`  [CERT] Using ${extractedCerts.chain.length} certs from original_handshake`);
                }
            }
        }

        if (!extractedCerts.chain) {
            return { reconstructed: null, error: `Certificate extraction failed: ${extractedCerts.error}`, streamData };
        }

        // Build reconstructed transaction (without certs first — pass null for extractedCertInfo)
        const reconstructed = buildNormalizedTransaction(claimed, null, parsedRequest, parsedResponse);

        // Build extracted certificate info from decrypted data
        const extractedCertInfo = {
            certificate_chain: extractedCerts.chain,  // EXTRACTED - independent proof
        };

        // Use extracted metadata for certificate_info fields
        if (extractedMetadata) {
            if (extractedMetadata.tlsVersion) extractedCertInfo.tls_version = extractedMetadata.tlsVersion;
            if (extractedMetadata.alpn) extractedCertInfo.alpn = extractedMetadata.alpn;
            // Get handshake proof from CertificateVerify
            const handshakeProof = extractedMetadata.getHandshakeProof();
            if (handshakeProof) {
                extractedCertInfo.handshake_proof = handshakeProof;
            }
        }

        // Use SNI extracted from ClientHello during certificate extraction
        if (extractedCerts.sni) {
            extractedCertInfo.sni = extractedCerts.sni;
        }

        // Infer cipher suite from keylog secret length
        const secretLen = keys.client_traffic_secret_0?.length || 0;
        if (secretLen === 64) {
            extractedCertInfo.cipher_suite = 'TLS_AES_128_GCM_SHA256';
        } else if (secretLen === 96) {
            extractedCertInfo.cipher_suite = 'TLS_AES_256_GCM_SHA384';
        }

        // For resumed sessions: RE-VALIDATE original_handshake instead of trusting claimed proof
        // SECURITY: Don't blindly copy handshake_proof - decrypt and verify
        if (!extractedCertInfo.handshake_proof && evidence.original_handshake) {
            if (verbose) {
                console.log(`  [RESUME] Re-validating original_handshake for resumed session`);
            }

            // Only verify SNI against original cert if we'll USE that cert chain
            // If we already extracted certs from current session, skip SNI check on original
            const needOriginalCerts = !extractedCertInfo.certificate_chain;
            const origValidation = await validateOriginalHandshake(evidence.original_handshake, {
                ...this.options,
                skipCtLookup: this.options.skipCtLookup,
                sni: needOriginalCerts ? extractedCertInfo.sni : null, // Only check SNI if using original's certs
            });

            if (!origValidation.valid) {
                return {
                    reconstructed: null,
                    error: `Original handshake validation failed: ${origValidation.error}`,
                    streamData: null,
                    certificateVerifyResult: null
                };
            }

            // Use validated values, not claimed values
            if (origValidation.handshake_proof) {
                extractedCertInfo.handshake_proof = origValidation.handshake_proof;
            }
            if (origValidation.certificate_chain && !extractedCertInfo.certificate_chain) {
                extractedCertInfo.certificate_chain = origValidation.certificate_chain;
            }

            if (verbose) {
                console.log(`  [RESUME] Original handshake validated successfully`);
            }
        }

        // Add EXTRACTED certificate info
        // NOTE: Do NOT copy from claimed data — only use what was extracted from the handshake.
        reconstructed.certificate_info = extractedCertInfo;

        return { reconstructed, error: null, streamData, certificateVerifyResult };
    }

    // NOTE: SNI extraction is now handled in quic-extractor.js during certificate extraction
    // The extractFromInitialPackets, decryptInitialPacket, etc. methods have been removed
    // in favor of reusing the working QuicDecryptor code path

    /**
     * Extract certificates from QUIC handshake packets
     * @param {Array} packets - Handshake packets with direction and data (base64)
     * @param {Object} keys - QUIC keys
     * @returns {Promise<{chain: Array|null, error: string|null}>}
     */
    async extractFromQuicHandshake(packets, keys) {
        const { verbose = false } = this.options;

        if (!packets || packets.length === 0) {
            return { chain: null, error: 'No handshake packets' };
        }

        try {
            return await extractFromQuicHandshake(packets, keys, { verbose });
        } catch (e) {
            if (verbose) console.log(`  Certificate extraction error: ${e.message}`);
            return { chain: null, error: e.message };
        }
    }
}
