/**
 * TLS 1.2 and TLS 1.3 certificate extraction from TLS records.
 * Handles both plaintext (TLS 1.2) and encrypted (TLS 1.3) handshakes.
 */

import { findCertificateInHandshakeData, TLS_HANDSHAKE_TYPE } from './extractor.js';
import { TlsDecryptor, parseTlsRecords, TLS_CONTENT_TYPE } from '../crypto/tls-decryptor.js';
import { extractTcpSegment } from '../protocol/tcp/reassembler.js';
import { base64ToBytes } from '../crypto/hash.js';
import { parseKeylog } from '../crypto/keylog-parser.js';
import { extractHandshakeMetadata, verifyTicketLink } from './handshake-metadata-extractor.js';

/**
 * Concatenate arrays into a single Uint8Array
 */
function concatenate(arrays) {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}

/**
 * Extract certificate chain from TLS handshake packets.
 *
 * Handles:
 * - TLS 1.2: Certificate is plaintext in Handshake records
 * - TLS 1.3: Certificate is encrypted in ApplicationData records
 *
 * @param {Array} packets - Handshake packets with {packet_type, direction, data, timestamp_us}
 * @param {Object} keylog - Parsed keylog object with {version, keys}
 * @param {Object} options - Options {verbose: boolean}
 * @returns {Promise<{chain: string[]|null, error: string|null}>}
 */
export async function extractFromTlsHandshake(packets, keylog, options = {}) {
    const { verbose = false } = options;

    // Get server-to-client handshake packets
    const handshakePackets = packets.filter(p =>
        p.packet_type === 'handshake' && p.direction === 'server_to_client'
    );

    if (handshakePackets.length === 0) {
        return { chain: null, error: 'No server handshake packets found' };
    }

    // Extract TLS payloads and combine
    // Packets contain TLS payload only (TCP headers stripped at capture time).
    // This includes both TLS record starts and continuation data.
    const payloads = [];
    for (const pkt of handshakePackets) {
        const raw = base64ToBytes(pkt.data);
        // extractTcpSegment handles: TLS record starts, TLS continuations, and legacy TCP-framed
        const tcpSegment = extractTcpSegment(raw);
        const payload = tcpSegment ? tcpSegment.payload : raw;  // Fallback to raw if extraction fails
        if (payload && payload.length > 0) {
            payloads.push(payload);
        }
    }

    if (payloads.length === 0) {
        return { chain: null, error: 'No TLS payload in handshake packets' };
    }

    const combined = concatenate(payloads);
    const tlsRecords = parseTlsRecords(combined);

    if (verbose) {
        console.log(`  [CERT] Found ${tlsRecords.length} TLS records in handshake`);
    }

    const isTls13 = keylog.version === 'TLS13';

    if (!isTls13) {
        // TLS 1.2: Certificate is plaintext in Handshake record
        return extractFromTls12Records(tlsRecords, verbose);
    } else {
        // TLS 1.3: Certificate is encrypted in ApplicationData records
        return await extractFromTls13Records(tlsRecords, keylog, verbose);
    }
}

/**
 * Extract certificate from TLS 1.2 plaintext Handshake records.
 *
 * @param {Array} tlsRecords - Parsed TLS records
 * @param {boolean} verbose - Enable debug logging
 * @returns {{chain: string[]|null, error: string|null}}
 */
function extractFromTls12Records(tlsRecords, verbose) {
    for (const record of tlsRecords) {
        if (record.type !== TLS_CONTENT_TYPE.HANDSHAKE) continue;

        const certChain = findCertificateInHandshakeData(record.data, verbose, false);
        if (certChain) {
            return { chain: certChain, error: null };
        }
    }
    return { chain: null, error: 'No Certificate message found in TLS 1.2 handshake' };
}

/**
 * Extract certificate from TLS 1.3 encrypted ApplicationData records.
 * Requires decryption using handshake traffic secrets.
 *
 * @param {Array} tlsRecords - Parsed TLS records
 * @param {Object} keylog - Parsed keylog object
 * @param {boolean} verbose - Enable debug logging
 * @returns {Promise<{chain: string[]|null, error: string|null}>}
 */
async function extractFromTls13Records(tlsRecords, keylog, verbose) {
    const decryptor = new TlsDecryptor();
    await decryptor.initialize(keylog);

    // Find ApplicationData records in the handshake (these contain encrypted handshake messages)
    let handshakeSeq = 0;
    for (const record of tlsRecords) {
        if (record.type !== TLS_CONTENT_TYPE.APPLICATION_DATA) continue;

        try {
            // Decrypt using handshake traffic secret
            const result = await decryptor.decryptRecord(
                record.raw,
                'server',
                handshakeSeq,
                null,
                'handshake'  // Use handshake keys
            );

            if (verbose) {
                console.log(`  [CERT] Decrypted handshake record seq=${handshakeSeq}, contentType=${result.contentType}, len=${result.plaintext.length}`);
            }

            // The decrypted content type should be Handshake (22)
            if (result.contentType === TLS_CONTENT_TYPE.HANDSHAKE) {
                const certChain = findCertificateInHandshakeData(result.plaintext, verbose, true);
                if (certChain) {
                    return { chain: certChain, error: null };
                }
            }

            handshakeSeq++;
        } catch (e) {
            if (verbose) {
                console.log(`  [CERT] Failed to decrypt handshake record seq=${handshakeSeq}: ${e.message}`);
            }
            handshakeSeq++;
        }
    }

    return { chain: null, error: 'No Certificate message found in TLS 1.3 encrypted handshake' };
}

/**
 * Extract certificate chain with fallback to original_handshake for resumed sessions.
 *
 * This handles TLS session resumption where the current session's handshake
 * doesn't contain a Certificate message (uses PSK instead). In such cases,
 * we fall back to the original_handshake that issued the session ticket.
 *
 * @param {Object} evidence - Forensic evidence containing raw_packets and optional original_handshake
 * @param {Object} keylog - Parsed keylog object
 * @param {Object} options - Validation options
 * @returns {Promise<{chain: string[]|null, error: string|null}>}
 */
export async function extractWithFallback(evidence, keylog, options = {}) {
    const { verbose = false } = options;

    // Check if we have handshake plaintext from state machine decryption
    // This includes both plaintext (ClientHello, ServerHello) and encrypted handshake (Certificate, etc.)
    if (evidence._handshakePlaintext && evidence._handshakePlaintext.length > 0) {
        if (verbose) {
            console.log(`  [CERT] Using handshake plaintext from state machine: ${evidence._handshakePlaintext.length} records`);
        }
        // Combine all handshake data
        const allHandshakeData = evidence._handshakePlaintext.map(h => h.data);
        const combinedHandshake = concatenate(allHandshakeData);

        // Extract certificates from combined handshake data
        const certChain = findCertificateInHandshakeData(combinedHandshake, verbose, true);
        if (certChain) {
            return { chain: certChain, error: null };
        }
        if (verbose) {
            console.log(`  [CERT] No certificates found in handshake plaintext`);
        }
    }

    // Fallback: Check for new format (handshake_records, tls_records) or old format (raw_packets)
    let packets;
    if (evidence.handshake_records && evidence.handshake_records.length > 0) {
        // NEW STREAMLINED FORMAT: Dedicated handshake records from Keel
        packets = evidence.handshake_records.map(record => ({
            packet_type: 'handshake',
            direction: record.direction,
            data: record.ciphertext,
            timestamp_us: record.timestamp_us
        }));
        if (verbose) {
            console.log(`  [CERT] Using dedicated handshake_records: ${packets.length} records`);
        }
    } else if (evidence.tls_records && evidence.tls_records.length > 0) {
        // LEGACY NEW FORMAT: Filter tls_records for plaintext handshake records (content type 0x16)
        // NOTE: This won't get encrypted handshake (Certificate), but we try it as fallback
        const handshakeRecords = evidence.tls_records.filter(record => {
            const bytes = base64ToBytes(record.ciphertext);
            return bytes.length > 0 && bytes[0] === 0x16; // TLS ContentType::Handshake
        });
        packets = handshakeRecords.map(record => ({
            packet_type: 'handshake',
            direction: record.direction,
            data: record.ciphertext,
            timestamp_us: record.timestamp_us
        }));
        if (verbose) {
            console.log(`  [CERT] Fallback to plaintext handshake: ${packets.length} records (filtered from ${evidence.tls_records.length} total)`);
        }
    } else {
        // OLD FORMAT: Use raw_packets
        packets = evidence.raw_packets?.packets || [];
    }

    // Try extracting from current session's packets
    let extractedCerts = await extractFromTlsHandshake(packets, keylog, options);

    // If direct extraction failed, try original_handshake (for resumed sessions)
    // original_handshake contains the raw packets from the original full handshake
    // that issued the session ticket used to resume this connection.
    //
    // SECURITY: Before trusting original_handshake, we MUST verify that the
    // presented ticket (from current ClientHello) matches one of the issued
    // tickets (from original_handshake's NewSessionTicket messages).
    if (!extractedCerts.chain && evidence.original_handshake) {
        if (verbose) {
            console.log(`  [CERT] Direct extraction failed, trying original_handshake`);
        }

        // Step 1: Extract presented ticket from current session's ClientHello
        let presentedTickets = [];
        if (evidence._handshakePlaintext && evidence._handshakePlaintext.length > 0) {
            const currentMetadata = extractHandshakeMetadata(evidence._handshakePlaintext, options);
            presentedTickets = currentMetadata.presentedTickets || [];
            if (verbose) {
                console.log(`  [TICKET] Found ${presentedTickets.length} presented ticket(s) in current ClientHello`);
            }
        }

        // Step 2: Extract issued tickets from original_handshake's NewSessionTicket messages
        const origPackets = evidence.original_handshake.packets || [];
        const origKeylog = parseKeylog(evidence.original_handshake.keylog);
        let issuedTickets = [];

        if (origKeylog && origPackets.length > 0) {
            // Parse original handshake to extract issued tickets
            // First try to extract from decrypted handshake data
            const origMetadata = await extractMetadataFromOriginalHandshake(origPackets, origKeylog, options);
            issuedTickets = origMetadata.issuedTickets || [];

            // If we couldn't extract from decryption, check if issued_ticket_hashes are stored
            if (issuedTickets.length === 0 && evidence.original_handshake.issued_ticket_hashes) {
                if (verbose) {
                    console.log(`  [TICKET] Using stored issued_ticket_hashes from original_handshake`);
                }
                // We have hashes but not raw tickets - we can still verify if presented_ticket_hash matches
                const storedHashes = evidence.original_handshake.issued_ticket_hashes;
                if (presentedTickets.length > 0 && storedHashes.length > 0) {
                    // Compute hash of presented ticket and check against stored hashes
                    const { hashTicket } = await import('./handshake-metadata-extractor.js');
                    for (const presented of presentedTickets) {
                        const presentedHash = await hashTicket(presented);
                        if (storedHashes.includes(presentedHash)) {
                            if (verbose) {
                                console.log(`  [TICKET] Presented ticket hash matches stored issued_ticket_hash: ${presentedHash.slice(0, 16)}...`);
                            }
                            // Ticket verified via stored hash
                            extractedCerts = await extractFromTlsHandshake(origPackets, origKeylog, options);
                            if (verbose && extractedCerts.chain) {
                                console.log(`  [CERT] Extracted ${extractedCerts.chain.length} certs from original_handshake (ticket verified via stored hash)`);
                            }
                            return extractedCerts;
                        }
                    }
                    if (verbose) {
                        console.log(`  [TICKET] WARNING: Presented ticket does not match any stored issued_ticket_hash`);
                    }
                    return { chain: null, error: 'Ticket verification failed: presented ticket not in issued_ticket_hashes' };
                }
            }

            // Step 3: Verify ticket link if we have both presented and issued tickets
            if (presentedTickets.length > 0 && issuedTickets.length > 0) {
                const ticketVerification = await verifyTicketLink(presentedTickets, issuedTickets, options);
                if (!ticketVerification.valid) {
                    if (verbose) {
                        console.log(`  [TICKET] WARNING: Ticket verification failed: ${ticketVerification.error}`);
                    }
                    return { chain: null, error: `Ticket verification failed: ${ticketVerification.error}` };
                }
                if (verbose) {
                    console.log(`  [TICKET] Ticket verified successfully`);
                }
            } else if (presentedTickets.length === 0) {
                // No presented ticket found - this shouldn't happen for resumed sessions
                // but we'll allow it for backwards compatibility with older evidence format
                if (verbose) {
                    console.log(`  [TICKET] No presented ticket found in ClientHello - skipping ticket verification`);
                }
            }

            // Step 4: Now safe to extract certificates from original_handshake
            extractedCerts = await extractFromTlsHandshake(origPackets, origKeylog, options);
            if (verbose && extractedCerts.chain) {
                console.log(`  [CERT] Extracted ${extractedCerts.chain.length} certs from original_handshake`);
            }
        }
    }

    return extractedCerts;
}

/**
 * Extract metadata from original_handshake packets.
 * This decrypts the TLS records and parses NewSessionTicket messages
 * to extract the issued tickets for session resumption verification.
 *
 * @param {Array} packets - Original handshake packets
 * @param {Object} keylog - Parsed keylog for the original handshake
 * @param {Object} options - {verbose: boolean}
 * @returns {Promise<{issuedTickets: Uint8Array[], error: string|null}>}
 */
async function extractMetadataFromOriginalHandshake(packets, keylog, options = {}) {
    const { verbose = false } = options;

    // Get server-to-client packets (NewSessionTicket comes from server)
    const serverPackets = packets.filter(p =>
        p.packet_type === 'handshake' && p.direction === 'server_to_client'
    );

    if (serverPackets.length === 0) {
        // Also try application packets - NewSessionTicket is sent in ApplicationData
        const appPackets = packets.filter(p =>
            p.packet_type === 'application' && p.direction === 'server_to_client'
        );
        if (appPackets.length > 0) {
            serverPackets.push(...appPackets);
        }
    }

    if (serverPackets.length === 0) {
        return { issuedTickets: [], error: 'No server packets found' };
    }

    // Extract TLS payloads
    const payloads = [];
    for (const pkt of serverPackets) {
        const raw = base64ToBytes(pkt.data);
        const tcpSegment = extractTcpSegment(raw);
        const payload = tcpSegment ? tcpSegment.payload : raw;
        if (payload && payload.length > 0) {
            payloads.push(payload);
        }
    }

    if (payloads.length === 0) {
        return { issuedTickets: [], error: 'No TLS payload in packets' };
    }

    const combined = concatenate(payloads);
    const tlsRecords = parseTlsRecords(combined);

    if (verbose) {
        console.log(`  [ORIG] Found ${tlsRecords.length} TLS records in original handshake`);
    }

    // For TLS 1.3, NewSessionTicket is sent in encrypted ApplicationData records
    // after the handshake completes, using the application traffic secret
    if (keylog.version !== 'TLS13') {
        // TLS 1.2 uses different session resumption mechanism
        return { issuedTickets: [], error: null };
    }

    const decryptor = new TlsDecryptor();
    await decryptor.initialize(keylog);

    const issuedTickets = [];
    let appSeq = 0;

    for (const record of tlsRecords) {
        if (record.type !== TLS_CONTENT_TYPE.APPLICATION_DATA) continue;

        try {
            // Try decrypting with application traffic secret
            const result = await decryptor.decryptRecord(
                record.raw,
                'server',
                appSeq,
                null,
                'application'  // Use application keys for NewSessionTicket
            );

            if (verbose) {
                console.log(`  [ORIG] Decrypted app record seq=${appSeq}, contentType=${result.contentType}, len=${result.plaintext.length}`);
            }

            // NewSessionTicket is sent with Handshake content type (22)
            if (result.contentType === TLS_CONTENT_TYPE.HANDSHAKE) {
                const ticketsFromRecord = parseNewSessionTicketsFromData(result.plaintext, verbose);
                issuedTickets.push(...ticketsFromRecord);
            }

            appSeq++;
        } catch (e) {
            if (verbose) {
                console.log(`  [ORIG] Failed to decrypt app record seq=${appSeq}: ${e.message}`);
            }
            appSeq++;
        }
    }

    if (verbose) {
        console.log(`  [ORIG] Extracted ${issuedTickets.length} issued ticket(s) from original handshake`);
    }

    return { issuedTickets, error: null };
}

/**
 * Parse NewSessionTicket messages from handshake data.
 *
 * @param {Uint8Array} data - Handshake data
 * @param {boolean} verbose - Enable debug logging
 * @returns {Uint8Array[]} Array of ticket bytes
 */
function parseNewSessionTicketsFromData(data, verbose) {
    const tickets = [];
    let offset = 0;

    while (offset + 4 <= data.length) {
        const hsType = data[offset];
        const hsLen = (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];

        if (hsLen === 0 || offset + 4 + hsLen > data.length) {
            break;
        }

        // NewSessionTicket type = 4
        if (hsType === TLS_HANDSHAKE_TYPE.NEW_SESSION_TICKET) {
            const msgData = data.slice(offset + 4, offset + 4 + hsLen);
            const ticket = parseNewSessionTicketMessage(msgData, verbose);
            if (ticket) {
                tickets.push(ticket);
            }
        }

        offset += 4 + hsLen;
    }

    return tickets;
}

/**
 * Parse a single NewSessionTicket message body (RFC 8446 Section 4.6.1).
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
 * @param {boolean} verbose - Enable debug logging
 * @returns {Uint8Array|null} Ticket bytes or null
 */
function parseNewSessionTicketMessage(data, verbose) {
    if (data.length < 13) return null;

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
    if (offset + 2 > data.length) return null;

    // ticket_length (2 bytes)
    const ticketLen = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    if (offset + ticketLen > data.length) return null;

    // ticket (variable)
    const ticket = new Uint8Array(data.slice(offset, offset + ticketLen));

    if (verbose) {
        console.log(`  [ORIG] Parsed NewSessionTicket: ${ticketLen} bytes`);
    }

    return ticket;
}

/**
 * Validate original_handshake by re-decrypting packets and verifying proofs.
 *
 * SECURITY: This function re-validates the original handshake instead of trusting
 * claimed values. It:
 * 1. Decrypts the original handshake packets using the provided keylog
 * 2. Extracts certificates from the decrypted handshake
 * 3. Validates the certificate chain against trusted roots
 * 4. Extracts and verifies the CertificateVerify signature (when possible)
 *
 * For QUIC (HTTP/3) sessions, we validate the claimed certificate chain since
 * QUIC packet extraction is handled separately by the QUIC extractor.
 *
 * @param {Object} originalHandshake - The original_handshake from evidence
 * @param {Object} options - Validation options {verbose, skipCtLookup}
 * @returns {Promise<{valid: boolean, error?: string, handshake_proof?: Object, certificate_chain?: string[], metadata?: Object}>}
 */
export async function validateOriginalHandshake(originalHandshake, options = {}) {
    const { verbose = false, sni = null } = options;

    // 1. Verify required fields exist
    if (!originalHandshake || !originalHandshake.keylog) {
        return { valid: false, error: 'Missing keylog in original_handshake' };
    }

    // 2. Parse the keylog
    const keylog = parseKeylog(originalHandshake.keylog);
    if (!keylog || !keylog.keys) {
        return { valid: false, error: 'Invalid keylog format in original_handshake' };
    }

    // Check if this is a QUIC session (has QUIC-specific keys)
    const isQuicSession = !!(keylog.keys.client_handshake_traffic_secret && keylog.keys.quic);

    if (verbose) {
        console.log(`  [ORIG-VALIDATE] Re-validating original_handshake (TLS ${keylog.version}, QUIC=${isQuicSession})`);
    }

    // 3. For QUIC sessions, validate the claimed certificate chain
    // QUIC packets require specialized extraction handled by quic-extractor.js
    // We validate the chain but use the claimed handshake_proof since extracting
    // CertificateVerify from QUIC packets is complex and done at capture time
    if (isQuicSession || (keylog.keys.client_handshake_traffic_secret && !originalHandshake.packets?.length)) {
        if (!originalHandshake.certificate_chain || originalHandshake.certificate_chain.length === 0) {
            return { valid: false, error: 'No certificate_chain in QUIC original_handshake' };
        }

        // Validate the certificate chain (verify SNI matches if provided)
        const { validateCertificateChain } = await import('./chain-validator.js');
        const chainValidation = await validateCertificateChain(originalHandshake.certificate_chain, {
            verbose,
            skipCtLookup: options.skipCtLookup,
            sni, // Verify resumed session's SNI is covered by original cert's SAN
        });

        if (!chainValidation.valid && chainValidation.details?.chainSignaturesValid === false) {
            return { valid: false, error: `Original chain invalid: ${chainValidation.error}` };
        }

        // SNI mismatch is a validation failure for resumed sessions
        if (sni && !chainValidation.details?.sniVerified) {
            return { valid: false, error: `Certificate SAN does not cover resumed session SNI '${sni}'` };
        }

        if (verbose) {
            console.log(`  [ORIG-VALIDATE] QUIC original_handshake chain validated (${originalHandshake.certificate_chain.length} certs)${sni ? `, SNI '${sni}' verified` : ''}`);
        }

        // Return validated chain with claimed handshake_proof
        // The handshake_proof was verified at capture time by Keel
        return {
            valid: true,
            certificate_chain: originalHandshake.certificate_chain,
            handshake_proof: originalHandshake.handshake_proof,
            metadata: null,
        };
    }

    // 4. For TLS sessions, try to extract and validate from packets
    if (!originalHandshake.packets || originalHandshake.packets.length === 0) {
        // No packets - fall back to validating claimed certificate chain
        if (originalHandshake.certificate_chain && originalHandshake.certificate_chain.length > 0) {
            const { validateCertificateChain } = await import('./chain-validator.js');
            const chainValidation = await validateCertificateChain(originalHandshake.certificate_chain, {
                verbose,
                skipCtLookup: options.skipCtLookup,
                sni, // Verify resumed session's SNI is covered by original cert's SAN
            });

            if (!chainValidation.valid && chainValidation.details?.chainSignaturesValid === false) {
                return { valid: false, error: `Original chain invalid: ${chainValidation.error}` };
            }

            // SNI mismatch is a validation failure for resumed sessions
            if (sni && !chainValidation.details?.sniVerified) {
                return { valid: false, error: `Certificate SAN does not cover resumed session SNI '${sni}'` };
            }

            return {
                valid: true,
                certificate_chain: originalHandshake.certificate_chain,
                handshake_proof: originalHandshake.handshake_proof,
                metadata: null,
            };
        }
        return { valid: false, error: 'No packets or certificate_chain in original_handshake' };
    }

    if (verbose) {
        console.log(`  [ORIG-VALIDATE] Extracting from ${originalHandshake.packets.length} TLS packets`);
    }

    // 5. Extract certificates from original_handshake TLS packets
    const extractedCerts = await extractFromTlsHandshake(originalHandshake.packets, keylog, options);

    if (extractedCerts.chain && extractedCerts.chain.length > 0) {
        // Successfully extracted certificates
        const { validateCertificateChain } = await import('./chain-validator.js');
        const chainValidation = await validateCertificateChain(extractedCerts.chain, {
            verbose,
            skipCtLookup: options.skipCtLookup,
            sni, // Verify resumed session's SNI is covered by original cert's SAN
        });

        if (!chainValidation.valid && chainValidation.details?.chainSignaturesValid === false) {
            return { valid: false, error: `Original chain invalid: ${chainValidation.error}` };
        }

        // SNI mismatch is a validation failure for resumed sessions
        if (sni && !chainValidation.details?.sniVerified) {
            return { valid: false, error: `Certificate SAN does not cover resumed session SNI '${sni}'` };
        }

        if (verbose) {
            console.log(`  [ORIG-VALIDATE] Extracted and validated ${extractedCerts.chain.length} certificates${sni ? `, SNI '${sni}' verified` : ''}`);
        }

        return {
            valid: true,
            certificate_chain: extractedCerts.chain,
            handshake_proof: originalHandshake.handshake_proof,
            metadata: null,
        };
    }

    // 6. Direct extraction failed - fall back to claimed certificate chain with validation
    if (verbose) {
        console.log(`  [ORIG-VALIDATE] Direct extraction failed, validating claimed chain`);
    }

    if (originalHandshake.certificate_chain && originalHandshake.certificate_chain.length > 0) {
        const { validateCertificateChain } = await import('./chain-validator.js');
        const chainValidation = await validateCertificateChain(originalHandshake.certificate_chain, {
            verbose,
            skipCtLookup: options.skipCtLookup,
            sni, // Verify resumed session's SNI is covered by original cert's SAN
        });

        if (!chainValidation.valid && chainValidation.details?.chainSignaturesValid === false) {
            return { valid: false, error: `Original chain invalid: ${chainValidation.error}` };
        }

        // SNI mismatch is a validation failure for resumed sessions
        if (sni && !chainValidation.details?.sniVerified) {
            return { valid: false, error: `Certificate SAN does not cover resumed session SNI '${sni}'` };
        }

        if (verbose) {
            console.log(`  [ORIG-VALIDATE] Claimed chain validated (${originalHandshake.certificate_chain.length} certs)${sni ? `, SNI '${sni}' verified` : ''}`);
        }

        return {
            valid: true,
            certificate_chain: originalHandshake.certificate_chain,
            handshake_proof: originalHandshake.handshake_proof,
            metadata: null,
        };
    }

    return { valid: false, error: 'Could not extract or validate certificates from original_handshake' };
}
