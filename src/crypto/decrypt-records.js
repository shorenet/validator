/**
 * TLS Record Decryption Functions
 *
 * High-level functions for decrypting TLS records from forensic evidence.
 * These functions use the TlsDecryptor class and handle the TLS 1.3 state machine.
 */

import { base64ToBytes } from './hash.js';
import { TlsDecryptor, parseTlsRecords, TLS_CONTENT_TYPE } from './tls-decryptor.js';
import { extractTlsPayload } from '../utils/payload.js';
import { extractTcpSegment } from '../protocol/tcp/reassembler.js';

/**
 * Decrypt TLS records using forensic evidence sequence numbers.
 *
 * This function implements a state machine that mirrors Rust's TLS 1.3 processing:
 * - Tracks handshake completion per-direction
 * - Uses stored tls_seq from forensic evidence for exact sequence matching
 * - Handles encrypted handshake and application data appropriately
 *
 * @param {Array} records - TLS records from forensic evidence
 * @param {Object} keylog - Parsed keylog data
 * @param {Object} options - Options {verbose: boolean}
 * @returns {Promise<{error: string|null, plaintext: Array, handshakePlaintext: Array}>}
 */
export async function decryptTlsRecords(records, keylog, options = {}) {
    const { verbose = false } = options;

    if (!records || records.length === 0) {
        return { error: 'No TLS records', plaintext: [], handshakePlaintext: [] };
    }

    // Initialize decryptor
    const decryptor = new TlsDecryptor();
    await decryptor.initialize(keylog);

    // State machine mirroring Rust's TLS 1.3 processing
    // Separate per-direction handshake complete flags (like Rust's TlsSession)
    //
    // IMPORTANT: Always use stored tls_seq from forensic evidence
    // - Rust now correctly tracks per-direction handshake completion
    // - Stored tls_seq is the actual AEAD sequence used for decryption
    // - HTTP/2 multiplexing causes gaps (other streams consume some seqs)
    //
    // BUG FIX: Track when we've ACTUALLY seen Finished messages
    // - In session resumption, server Finished may be in a separate TLS record
    // - Can't assume server handshake complete just because we saw client Finished
    // - Must track each direction independently
    let clientHandshakeComplete = false;
    let serverHandshakeComplete = false;

    const allPlaintext = [];
    const handshakePlaintext = [];

    if (verbose) {
        console.log(`  Processing ${records.length} TLS records with state machine`);
    }

    // Helper: Check if direction is still in handshake phase
    // Mirrors Rust's: session.in_handshake_phase(is_from_client)
    const inHandshakePhase = (isClient) => {
        return isClient ? !clientHandshakeComplete : !serverHandshakeComplete;
    };

    // Helper: Mark handshake complete for a direction
    // Mirrors Rust's: session.complete_handshake(is_from_client)
    const completeHandshake = (isClient) => {
        if (isClient) {
            clientHandshakeComplete = true;
        } else {
            serverHandshakeComplete = true;
        }
        if (verbose) {
            console.log(`  [${isClient ? 'client' : 'server'}] Handshake complete`);
        }
    };

    // Process records in TIMESTAMP ORDER (arrival order)
    // This is critical for TLS 1.3: handshake_seq and app_seq are SEPARATE counters,
    // both starting at 0. Without timestamp ordering, an app data record with seq=2
    // might be processed BEFORE Server Finished (seq=3), causing wrong key usage.
    // By processing in arrival order, the state machine naturally sees Finished first.
    const sortedRecords = [...records].sort((a, b) =>
        (a.timestamp_us || 0) - (b.timestamp_us || 0)
    );

    for (const record of sortedRecords) {
        const ciphertext = base64ToBytes(record.ciphertext);
        const direction = record.direction === 'client_to_server' ? 'client' : 'server';
        const isClient = direction === 'client';

        if (verbose) {
            console.log(`  Processing record: tls_seq=${record.tls_seq} direction=${record.direction} (${direction})`);
        }

        // Parse the TLS record (5-byte header + encrypted payload)
        const parsedRecords = parseTlsRecords(ciphertext);

        if (parsedRecords.length === 0) {
            if (verbose) {
                console.log(`  [${direction}] seq ${record.tls_seq}: Failed to parse TLS record`);
            }
            continue;
        }

        const tlsRecord = parsedRecords[0];

        // Plaintext handshake (ClientHello, ServerHello)
        if (tlsRecord.type === TLS_CONTENT_TYPE.HANDSHAKE) {
            if (verbose) {
                console.log(`  [${direction}] Plaintext handshake (type 0x16)`);
            }
            // Store for certificate extraction (parseTlsRecords uses .data not .payload)
            handshakePlaintext.push({ direction, data: tlsRecord.data });
            continue;
        }

        // Encrypted records (0x17)
        if (tlsRecord.type === TLS_CONTENT_TYPE.APPLICATION_DATA) {
            // Mirrors Rust: if in_handshake && has_handshake_secrets
            if (inHandshakePhase(isClient)) {
                // Encrypted handshake (Certificate, CertificateVerify, Finished)
                // Use stored tls_seq from forensic evidence (Rust now has per-direction tracking)

                if (verbose) {
                    console.log(`  [${direction}] Decrypting as encrypted handshake (tls_seq ${record.tls_seq})`);
                    console.log(`  [${direction}] Has handshake keys: client=${!!decryptor.handshakeClientKeys}, server=${!!decryptor.handshakeServerKeys}`);
                }

                try {
                    const decrypted = await decryptor.decryptRecord(
                        tlsRecord.raw,
                        direction,
                        0,  // hintSeq not used when tlsRecordSeq provided
                        record.tls_seq,  // Use stored tls_seq from forensic evidence
                        'handshake'
                    );

                    // Check inner content type (returned by decryptTls13Record, NOT from plaintext)
                    // decryptTls13Record already strips the content type byte and returns it in contentType
                    if (decrypted.plaintext.length > 0) {
                        const innerType = decrypted.contentType;

                        if (verbose) {
                            console.log(`  [${direction}] Decrypted ${decrypted.plaintext.length} bytes, inner type: 0x${innerType.toString(16)}`);
                        }

                        if (innerType === 0x16) {
                            // Encrypted handshake - already stripped by decryptTls13Record
                            const innerData = decrypted.plaintext;
                            handshakePlaintext.push({ direction, data: innerData });

                            if (verbose) {
                                console.log(`  [${direction}] Encrypted handshake (tls_seq ${record.tls_seq}): ${innerData.length} bytes`);
                            }

                            // Check for Finished message (0x14) - mirrors Rust tls13.rs:324-338
                            // Parse through all handshake messages to find Finished
                            let offset = 0;
                            let foundFinished = false;
                            while (offset + 4 <= innerData.length) {
                                const msgType = innerData[offset];
                                const msgLen = (innerData[offset + 1] << 16) | (innerData[offset + 2] << 8) | innerData[offset + 3];

                                if (verbose) {
                                    const msgTypeName = msgType === 0x08 ? 'EncryptedExtensions' :
                                                       msgType === 0x0b ? 'Certificate' :
                                                       msgType === 0x0f ? 'CertificateVerify' :
                                                       msgType === 0x14 ? 'Finished' : `Unknown(${msgType})`;
                                    console.log(`  [${direction}]   Handshake msg: ${msgTypeName} (len=${msgLen})`);
                                }

                                if (msgType === 0x14) { // Finished
                                    foundFinished = true;
                                    if (verbose) {
                                        console.log(`  [${direction}] Detected Finished message`);
                                    }
                                    completeHandshake(isClient);
                                    break; // Stop after Finished
                                }

                                // Move to next message (4-byte header + message body)
                                offset += 4 + msgLen;
                                if (offset > innerData.length) break; // Malformed, stop
                            }

                            if (verbose && !foundFinished) {
                                console.log(`  [${direction}] WARNING: No Finished message found in encrypted handshake`);
                            }
                        } else if (innerType === 0x17) {
                            // Application data during handshake phase - auto-transition
                            // Mirrors Rust tls13.rs:347-356
                            if (verbose) {
                                console.log(`  [${direction}] Application data during handshake - auto-transitioning`);
                            }
                            completeHandshake(isClient);

                            // BUG FIX: Also add this record to application data - it contains HTTP/2 frames!
                            // Without this, the first application data record (with HEADERS) was being lost.
                            allPlaintext.push({
                                direction,
                                data: decrypted.plaintext,
                                frame_offset: record.frame_offset || 0,
                                headers_offsets: record.headers_offsets || null
                            });
                            if (verbose) {
                                console.log(`  [${direction}] Application data (transitional, tls_seq ${record.tls_seq}): ${decrypted.plaintext.length} bytes, frame_offset=${record.frame_offset || 0}, headers_offsets=${JSON.stringify(record.headers_offsets)}`);
                            }
                        }
                    }
                } catch (e) {
                    if (verbose) {
                        console.log(`  [${direction}] Encrypted handshake decrypt failed (tls_seq ${record.tls_seq}): ${e.message}`);
                    }
                    return { error: `Encrypted handshake decryption failed: ${e.message}`, plaintext: [], handshakePlaintext: [] };
                }
            } else {
                // Application data - use stored tls_seq from forensic evidence
                // HTTP/2 multiplexing causes gaps in seq numbers (other streams consume some seqs)
                // Validator MUST use stored tls_seq, not compute its own counter
                const storedSeq = record.tls_seq;

                if (verbose) {
                    console.log(`  [${direction}] Decrypting application data (tls_seq ${storedSeq})`);
                }

                try {
                    const decrypted = await decryptor.decryptRecord(
                        tlsRecord.raw,
                        direction,
                        0,  // hintSeq (not used when tlsRecordSeq provided)
                        storedSeq,  // Use stored tls_seq from forensic evidence
                        'application'
                    );

                    // Check inner content type (returned by decryptTls13Record, NOT from plaintext)
                    // decryptTls13Record already strips the content type byte and returns it in contentType
                    if (decrypted.plaintext.length > 0) {
                        const innerType = decrypted.contentType;

                        if (innerType === 0x17) {
                            // Application data - already stripped by decryptTls13Record
                            // Include frame_offset for HTTP/2 multiplexing - indicates where
                            // the first frame for THIS stream starts within this record
                            // Include headers_offsets for HPACK reconstruction - locations of HEADERS frames
                            allPlaintext.push({
                                direction,
                                data: decrypted.plaintext,
                                frame_offset: record.frame_offset || 0,
                                headers_offsets: record.headers_offsets || null
                            });

                            if (verbose) {
                                console.log(`  [${direction}] Application data (tls_seq ${storedSeq}): ${decrypted.plaintext.length} bytes, frame_offset=${record.frame_offset || 0}, headers_offsets=${JSON.stringify(record.headers_offsets)}`);
                            }
                        } else if (innerType === 0x16) {
                            // Post-handshake message (NewSessionTicket, etc.) - ignore
                            if (verbose) {
                                console.log(`  [${direction}] Post-handshake message (tls_seq ${storedSeq}): ignored`);
                            }
                        }
                    }
                } catch (e) {
                    if (verbose) {
                        console.log(`  [${direction}] Application data decrypt failed (tls_seq ${storedSeq}): ${e.message}`);
                    }
                    return { error: `Application data decryption failed: ${e.message}`, plaintext: [], handshakePlaintext: [] };
                }
            }
        }
    }

    if (verbose) {
        console.log(`  State machine complete: ${allPlaintext.length} app records, ${handshakePlaintext.length} handshake records`);
    }

    return { error: null, plaintext: allPlaintext, handshakePlaintext };
}

/**
 * Extract server random from TLS handshake packets.
 *
 * Used for TLS 1.2 where the server random is needed for key derivation
 * but may not be in the keylog file.
 *
 * @param {Array} packets - Raw packets from forensic evidence
 * @returns {Uint8Array|null} 32-byte server random or null if not found
 */
export function extractServerRandom(packets) {
    for (const pkt of packets) {
        if (pkt.direction !== 'server_to_client') continue;

        const data = base64ToBytes(pkt.data);
        // Extract TLS payload from TCP-framed packet
        const tcpSegment = extractTcpSegment(data);
        const tlsPayload = tcpSegment ? tcpSegment.payload : extractTlsPayload(data);
        if (!tlsPayload || tlsPayload.length === 0) continue;

        // Look for TLS handshake records
        let offset = 0;
        while (offset + 5 <= tlsPayload.length) {
            const contentType = tlsPayload[offset];
            const recordLen = (tlsPayload[offset + 3] << 8) | tlsPayload[offset + 4];

            if (contentType !== 22) { // Not handshake
                offset += 5 + recordLen;
                continue;
            }

            if (offset + 5 + 38 > tlsPayload.length) {
                offset += 5 + recordLen;
                continue;
            }

            const hsType = tlsPayload[offset + 5];
            if (hsType === 0x02) { // ServerHello
                // ServerHello: type(1) + len(3) + version(2) + random(32)
                const randomOffset = offset + 5 + 1 + 3 + 2;
                if (randomOffset + 32 <= tlsPayload.length) {
                    return tlsPayload.slice(randomOffset, randomOffset + 32);
                }
            }

            offset += 5 + recordLen;
        }
    }
    return null;
}
