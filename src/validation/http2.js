/**
 * HTTP/2 Validator
 * Validates HTTP/2 transactions using forensic evidence
 *
 * SECURITY MODEL: "Extract Everything, Trust Nothing"
 * =================================================
 *
 * This validator follows a strict trust model:
 *
 * TRUSTED (cryptographically bound):
 * - tls_records / raw_packets (encrypted bytes)
 * - keylog (if wrong, decryption fails)
 *
 * NOT TRUSTED (must extract from packets):
 * - certificate_info.* (extract from Certificate message)
 * - handshake_proof.* (extract from CertificateVerify)
 * - All metadata (extract from decrypted packets)
 *
 * VALIDATION APPROACH:
 * 1. EXTRACTED values (from decrypted packets) → used for security decisions
 *    - CertificateVerify verification
 *    - Chain validation against Mozilla roots
 *    - SNI verification against certificate SANs
 *
 * 2. CLAIMED values (from evidence JSON) → used only for hash comparison
 *    - The "original" transaction is built from claimed values
 *    - The "reconstructed" transaction is built from extracted values
 *    - Hash match proves claimed == extracted
 *
 * 3. For resumed sessions (original_handshake):
 *    - Re-validate the original handshake, don't blindly trust claimed proof
 *    - Verify ticket binding: presented ticket must match issued ticket
 *
 * See docs/SECURITY_HARDENING_PLAN.md for full security analysis.
 */

import { BaseValidator } from './base-validator.js';
import { Http2Reconstructor } from '../reconstruction/http2.js';
import { parseKeylog } from '../crypto/keylog-parser.js';
import { decryptTlsRecords, extractServerRandom } from '../crypto/decrypt-records.js';
import { extractWithFallback, validateOriginalHandshake } from '../certificate/tls-extractor.js';
import { extractHandshakeMetadata, computeTranscriptHash, verifyCertificateVerifySignature, verifyServerKeyExchangeSignature } from '../certificate/handshake-metadata-extractor.js';
import { validateCertificateChain } from '../certificate/chain-validator.js';
import {
    findDifferences,
    normalizeHeaders,
    normalizeForValidation,
    hashTransaction,
    concatenate
} from '../utils/helpers.js';
import { parseFrames, FrameType, extractHeaderBlock } from '../protocol/http2/frame-parser.js';
import { HpackDecoder } from '../protocol/http2/hpack-decoder.js';

export class Http2Validator extends BaseValidator {
    constructor(options = {}) {
        super(options);
        this.reconstructor = options.reconstructor || new Http2Reconstructor(options);
    }

    /**
     * Validate HTTP/2 transaction
     * @param {Object} evidence - Forensic evidence (for cryptographic work)
     * @param {Object} claimed - Claimed data (for final hash comparison only)
     * @returns {Promise<ValidationResult>}
     */
    async validate(evidence, claimed) {
        const result = this.createResult();
        const { verbose = false } = this.options;

        // Check required fields
        const streamId = evidence.stream_id;
        if (!streamId) {
            result.error = 'Missing stream_id';
            return result;
        }

        // Parse keylog
        const keylog = parseKeylog(evidence.keylog);
        if (!keylog) {
            result.error = 'Invalid keylog';
            return result;
        }

        // Handle TLS 1.2 server_random
        if (keylog.version === 'TLS12') {
            if (evidence.server_random) {
                keylog.server_random = evidence.server_random;
            } else {
                const serverRandom = extractServerRandom(evidence.raw_packets?.packets || []);
                if (serverRandom) {
                    keylog.server_random = Array.from(serverRandom)
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join('');
                }
            }
        }

        // Require tls_records for HTTP/2
        if (!evidence.tls_records || evidence.tls_records.length === 0) {
            result.error = 'Missing tls_records in evidence';
            return result;
        }

        if (verbose) {
            console.log(`  Processing ${evidence.tls_records.length} TLS records`);
        }

        // Decrypt TLS records
        const decryptResult = await decryptTlsRecords(evidence.tls_records, keylog, this.options);
        if (decryptResult.handshakePlaintext) {
            evidence._handshakePlaintext = decryptResult.handshakePlaintext;
        }

        if (decryptResult.error) {
            result.error = decryptResult.error;
            return result;
        }

        const allPlaintext = decryptResult.plaintext;
        if (allPlaintext.length === 0) {
            result.error = 'Decryption failed';
            return result;
        }

        result.level = 'decrypt';
        result.valid = true;

        // Initialize fresh HPACK decoders - table builds up as we process ALL HEADERS frames.
        // This is the key insight: HPACK state is deterministic, so processing all HEADERS
        // frames in order from decrypted TLS records produces the same table state.
        const requestHpack = new HpackDecoder();
        const responseHpack = new HpackDecoder();

        // Parse HTTP/2 frames - processes ALL HEADERS to build table, extracts target stream
        const { parsedRequest, parsedResponse, foundRequestHeaders, foundResponseHeaders } =
            this.parseHttp2Frames(allPlaintext, streamId, requestHpack, responseHpack, verbose);

        if (foundRequestHeaders || foundResponseHeaders) {
            result.level = 'parse';
            result.details.parsedRequest = parsedRequest;
            result.details.parsedResponse = parsedResponse;
        }

        // Full validation via hash comparison
        if (parsedRequest && claimed.request) {
            const extractedCerts = await extractWithFallback(evidence, keylog, this.options);

            if (extractedCerts.chain) {
                if (verbose) {
                    console.log(`  Extracted ${extractedCerts.chain.length} certificates from TLS handshake`);
                }
            } else {
                if (verbose) {
                    console.log(`  Certificate extraction failed: ${extractedCerts.error}`);
                }
                result.details.certExtractionFailed = extractedCerts.error || 'unknown';
                return result;
            }

            // Extract metadata from decrypted handshake (SNI, TLS version, cipher suite, ALPN, CertificateVerify)
            let extractedMetadata = null;
            if (evidence._handshakePlaintext && evidence._handshakePlaintext.length > 0) {
                extractedMetadata = extractHandshakeMetadata(evidence._handshakePlaintext, this.options);
                if (verbose && extractedMetadata) {
                    console.log(`  [META] Extracted: SNI=${extractedMetadata.sni}, version=${extractedMetadata.tlsVersion}, cipher=${extractedMetadata.cipherSuite}, ALPN=${extractedMetadata.alpn}`);
                }
            }

            // Build extracted certificate info from decrypted data
            const extractedCertInfo = {
                certificate_chain: extractedCerts.chain,
            };

            // Use extracted metadata for certificate_info fields
            if (extractedMetadata) {
                if (extractedMetadata.sni) extractedCertInfo.sni = extractedMetadata.sni;
                if (extractedMetadata.tlsVersion) extractedCertInfo.tls_version = extractedMetadata.tlsVersion;
                if (extractedMetadata.cipherSuite) extractedCertInfo.cipher_suite = extractedMetadata.cipherSuite;
                if (extractedMetadata.alpn) extractedCertInfo.alpn = extractedMetadata.alpn;
                // Get handshake proof from either CertificateVerify (TLS 1.3) or ServerKeyExchange (TLS 1.2)
                const handshakeProof = extractedMetadata.getHandshakeProof();
                if (handshakeProof) {
                    extractedCertInfo.handshake_proof = handshakeProof;
                }
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
                    result.level = 'none';
                    result.valid = false;
                    result.error = `Original handshake validation failed: ${origValidation.error}`;
                    return result;
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

            // Verify CertificateVerify signature (cryptographic proof of server identity)
            if (extractedMetadata?.certificateVerify && extractedCerts.chain?.length > 0) {
                const transcriptResult = await computeTranscriptHash(evidence._handshakePlaintext, {
                    ...this.options,
                    cipherSuite: extractedCertInfo.cipher_suite || '',
                });

                if (transcriptResult.hash) {
                    const verifyResult = await verifyCertificateVerifySignature(
                        extractedMetadata.certificateVerify,
                        transcriptResult.hash,
                        extractedCerts.chain[0], // leaf certificate
                        this.options
                    );

                    result.details.certificateVerifySignature = {
                        verified: verifyResult.valid,
                        error: verifyResult.error,
                    };

                    if (verbose) {
                        console.log(`  [VERIFY] CertificateVerify signature: ${verifyResult.valid ? 'VALID' : 'INVALID'}`);
                        if (verifyResult.error) {
                            console.log(`  [VERIFY] Error: ${verifyResult.error}`);
                        }
                    }
                } else if (verbose) {
                    console.log(`  [VERIFY] Could not compute transcript hash: ${transcriptResult.error}`);
                }
            }

            // SECURITY: Enforce CertificateVerify - if verification was attempted and failed, reject
            if (result.details.certificateVerifySignature && !result.details.certificateVerifySignature.verified) {
                result.level = 'none';
                result.valid = false;
                result.error = `CertificateVerify signature invalid: ${result.details.certificateVerifySignature.error || 'signature mismatch'}`;
                return result;
            }

            // Verify ServerKeyExchange signature for TLS 1.2 (ECDHE)
            // This proves the server controls the private key for the certificate
            if (extractedMetadata?.serverKeyExchange && !extractedMetadata?.certificateVerify && extractedCerts.chain?.length > 0) {
                const clientRandom = keylog?.client_random;
                const serverRandom = keylog?.server_random || keylog?.keys?.server_random;

                if (clientRandom && serverRandom) {
                    const verifyResult = await verifyServerKeyExchangeSignature(
                        extractedMetadata.serverKeyExchange,
                        clientRandom,
                        serverRandom,
                        extractedCerts.chain[0], // leaf certificate
                        this.options
                    );

                    result.details.serverKeyExchangeSignature = {
                        verified: verifyResult.valid,
                        error: verifyResult.error,
                    };

                    if (verbose) {
                        console.log(`  [VERIFY] ServerKeyExchange signature (TLS 1.2): ${verifyResult.valid ? 'VALID' : 'INVALID'}`);
                        if (verifyResult.error) {
                            console.log(`  [VERIFY] Error: ${verifyResult.error}`);
                        }
                    }
                } else if (verbose) {
                    console.log(`  [VERIFY] Cannot verify ServerKeyExchange: missing client_random or server_random`);
                }
            }

            // SECURITY: Enforce ServerKeyExchange - if verification was attempted and failed, reject
            if (result.details.serverKeyExchangeSignature && !result.details.serverKeyExchangeSignature.verified) {
                result.level = 'none';
                result.valid = false;
                result.error = `ServerKeyExchange signature invalid (TLS 1.2): ${result.details.serverKeyExchangeSignature.error || 'signature mismatch'}`;
                return result;
            }

            // SECURITY: Validate certificate chain (CT lookup + chain signatures + SNI verification)
            const chainValidation = await validateCertificateChain(extractedCerts.chain, {
                sni: extractedCertInfo.sni,
                verbose,
                evidenceTimestamp: claimed.request?.timestamp_us,
                skipCtLookup: this.options.skipCtLookup,
            });

            result.details.chainValidation = {
                valid: chainValidation.valid,
                level: chainValidation.level,
                error: chainValidation.error,
                sniVerified: chainValidation.details?.sniVerified,
                chainSignaturesValid: chainValidation.details?.chainSignaturesValid,
                ctFound: chainValidation.details?.ctLookup?.found,
            };

            if (verbose) {
                console.log(`  [CHAIN] Validation: ${chainValidation.valid ? 'VALID' : 'INVALID'} (level=${chainValidation.level})`);
                if (chainValidation.error) {
                    console.log(`  [CHAIN] Error: ${chainValidation.error}`);
                }
            }

            // SECURITY: Enforce chain validation - if chain signatures failed, reject
            // Note: CT lookup failures are warnings, not hard failures (network issues)
            if (!chainValidation.valid && chainValidation.details?.chainSignaturesValid === false) {
                result.level = 'none';
                result.valid = false;
                result.error = `Certificate chain invalid: ${chainValidation.error}`;
                return result;
            }

            // Normalize original using CLAIMED data (what was captured)
            const original = normalizeForValidation(claimed);

            // Build reconstructed from parsed data + EXTRACTED certs ONLY (what we decrypted)
            // NOTE: Do NOT fall back to claimed values - that would negate validation.
            // If extracted is missing fields, they stay missing. The hash comparison will
            // detect mismatches between claimed (original) and extracted (reconstructed).
            const reconstructedUrl = parsedRequest.scheme && parsedRequest.authority && parsedRequest.path
                ? `${parsedRequest.scheme}://${parsedRequest.authority}${parsedRequest.path}`
                : claimed.request.url;

            const reconstructed = {
                id: claimed.id,
                protocol: claimed.protocol,
                request: {
                    method: parsedRequest.method,
                    url: reconstructedUrl,
                    headers: normalizeHeaders(parsedRequest.headers),
                },
                response: parsedResponse ? {
                    status: parsedResponse.status,
                    headers: normalizeHeaders(parsedResponse.headers),
                } : null,
                connection: claimed.connection ? {
                    id: claimed.connection.id,
                    client_addr: claimed.connection.client_addr,
                    server_addr: claimed.connection.server_addr,
                } : null,
                certificate_info: extractedCertInfo.certificate_chain ? {
                    sni: extractedCertInfo.sni,
                    tls_version: extractedCertInfo.tls_version,
                    alpn: extractedCertInfo.alpn,
                    cipher_suite: extractedCertInfo.cipher_suite,
                    certificate_chain: extractedCertInfo.certificate_chain,
                    handshake_proof: extractedCertInfo.handshake_proof,
                } : null,
            };

            // Compare via hash
            const originalHash = await hashTransaction(original);
            const reconstructedHash = await hashTransaction(reconstructed);
            const fullMatch = originalHash === reconstructedHash;

            if (fullMatch) {
                result.level = 'full';
                result.details.matched = 'hash';
            } else {
                const differences = findDifferences(original, reconstructed);
                result.details.hashMismatch = {
                    originalHash,
                    reconstructedHash,
                    differences,
                };

                if (verbose) {
                    console.log(`  Original hash:      ${originalHash}`);
                    console.log(`  Reconstructed hash: ${reconstructedHash}`);
                    console.log(`  Differences (${differences.length}):`);
                    for (const diff of differences.slice(0, 10)) {
                        console.log(`    ${diff}`);
                    }
                }
            }
        }

        return result;
    }

    /**
     * Parse HTTP/2 frames from decrypted plaintext.
     *
     * CRITICAL: Must process ALL HEADERS frames in order to build HPACK table state.
     * The table is deterministic - same sequence of HEADERS produces same state.
     * We can't skip frames for other streams because they update the shared table.
     */
    parseHttp2Frames(allPlaintext, streamId, requestHpack, responseHpack, verbose) {
        let parsedRequest = null;
        let parsedResponse = null;
        let foundRequestHeaders = false;
        let foundResponseHeaders = false;

        // Helper to strip HTTP/2 connection preface
        const stripPreface = (data) => {
            const preface = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';
            const prefaceBytes = new TextEncoder().encode(preface);
            if (data.length >= prefaceBytes.length) {
                let isPreface = true;
                for (let i = 0; i < prefaceBytes.length; i++) {
                    if (data[i] !== prefaceBytes[i]) { isPreface = false; break; }
                }
                if (isPreface) return data.slice(prefaceBytes.length);
            }
            return data;
        };

        // Process ALL HEADERS frames to build table, extract target stream's headers
        const processFrames = (frames, targetStreamId, decoder, isRequest) => {
            let result = null;
            for (const frame of frames) {
                if (frame.type !== FrameType.HEADERS) continue;

                try {
                    const headerBlock = extractHeaderBlock(frame.payload, frame.flags);
                    // Decode ALL frames - this builds the dynamic table
                    const headers = decoder.decode(headerBlock);

                    // Only extract result for target stream
                    if (frame.streamId === targetStreamId) {
                        const headerMap = {};
                        for (const [name, value] of headers) {
                            headerMap[name] = value;
                        }
                        if (isRequest) {
                            result = {
                                method: headerMap[':method'],
                                path: headerMap[':path'],
                                authority: headerMap[':authority'],
                                scheme: headerMap[':scheme'],
                                headers: headerMap
                            };
                        } else {
                            result = {
                                status: parseInt(headerMap[':status'], 10),
                                headers: headerMap
                            };
                        }
                        if (verbose) {
                            console.log(`  [HPACK] Decoded target stream ${targetStreamId} headers`);
                        }
                    } else if (verbose) {
                        console.log(`  [HPACK] Processed stream ${frame.streamId} headers (table update)`);
                    }
                } catch (e) {
                    if (verbose) console.log(`  HPACK decode error on stream ${frame.streamId}: ${e.message}`);
                }
            }
            return result;
        };

        // Collect plaintext by direction
        const clientData = [];
        const serverData = [];
        for (const { direction, data } of allPlaintext) {
            if (direction === 'client') {
                clientData.push(stripPreface(data));
            } else {
                serverData.push(data);
            }
        }

        if (verbose) {
            console.log(`  allPlaintext: ${allPlaintext.length} records (client: ${clientData.length}, server: ${serverData.length})`);
        }

        // Parse frames with headers_offsets for HPACK and frame_offset for stream data.
        // CRITICAL: Avoid duplicates by tracking what we've added per-record.
        // Key includes record index because offset 0 in record A is different from offset 0 in record B.
        const allFrames = { client: [], server: [] };
        const seenFrames = { client: new Set(), server: new Set() };

        let recordIndex = 0;
        for (const { direction, data, frame_offset, headers_offsets } of allPlaintext) {
            let frameData = direction === 'client' ? stripPreface(data) : data;

            // Parse HEADERS at headers_offsets for HPACK table building
            if (headers_offsets && headers_offsets.length > 0) {
                for (const hdrOffset of headers_offsets) {
                    // Key includes record index to distinguish same offset in different records
                    const key = `${recordIndex}:${hdrOffset}`;
                    if (hdrOffset < frameData.length && !seenFrames[direction].has(key)) {
                        try {
                            const frames = parseFrames(frameData.slice(hdrOffset));
                            if (frames.length > 0 && (frames[0].type === FrameType.HEADERS || frames[0].type === FrameType.CONTINUATION)) {
                                allFrames[direction].push(frames[0]);
                                seenFrames[direction].add(key);
                                if (verbose) {
                                    console.log(`  [${direction}] HPACK: Parsed ${frames[0].typeName || 'HEADERS'} at offset ${hdrOffset} (stream=${frames[0].streamId})`);
                                }
                            }
                        } catch (e) {
                            if (verbose) {
                                console.log(`  [${direction}] HPACK parse error at offset ${hdrOffset}: ${e.message}`);
                            }
                        }
                    }
                }
            }

            // Parse from frame_offset for this stream's frames (DATA, etc.)
            // Skip HEADERS that were already parsed above from headers_offsets
            const offset = frame_offset || 0;
            let streamFrameData = frameData;
            if (offset > 0 && offset < frameData.length) {
                if (verbose) {
                    console.log(`  [${direction}] Stream: Skipping to frame_offset=${offset}`);
                }
                streamFrameData = frameData.slice(offset);
            }

            try {
                const frames = parseFrames(streamFrameData);
                for (const frame of frames) {
                    // Skip HEADERS/CONTINUATION that were already added from headers_offsets
                    if (frame.type === FrameType.HEADERS || frame.type === FrameType.CONTINUATION) {
                        // Key includes record index to match the headers_offsets key format
                        const key = `${recordIndex}:${offset}`;
                        if (seenFrames[direction].has(key)) {
                            continue; // Already added from headers_offsets
                        }
                    }
                    allFrames[direction].push(frame);
                }
                if (verbose && frames.length > 0) {
                    console.log(`  [${direction}] Parsed ${frames.length} frames: ${frames.map(f => `${f.typeName || 'TYPE_' + f.type}(stream=${f.streamId})`).join(', ')}`);
                }
            } catch (e) {
                if (verbose) {
                    console.log(`  [${direction}] Frame parse error: ${e.message}`);
                }
            }

            recordIndex++;
        }

        // Process ALL frames in order - table builds up correctly
        parsedRequest = processFrames(allFrames.client, streamId, requestHpack, true);
        if (parsedRequest) {
            foundRequestHeaders = true;
            if (verbose) console.log(`  Found request: ${parsedRequest.method} ${parsedRequest.path}`);
        }

        parsedResponse = processFrames(allFrames.server, streamId, responseHpack, false);
        if (parsedResponse) {
            foundResponseHeaders = true;
            if (verbose) console.log(`  Found response: ${parsedResponse.status}`);
        }

        // Try combined approach if per-record didn't find headers
        if (!foundRequestHeaders && clientData.length > 1) {
            const combined = concatenate(clientData);
            try {
                const frames = parseFrames(combined);
                // Reset decoder and process fresh - combined data is a new sequence
                requestHpack.reset();
                parsedRequest = processFrames(frames, streamId, requestHpack, true);
                if (parsedRequest) {
                    foundRequestHeaders = true;
                    if (verbose) console.log(`  Found request (combined): ${parsedRequest.method} ${parsedRequest.path}`);
                }
            } catch (e) {
                if (verbose) console.log(`  Combined client parse error: ${e.message}`);
            }
        }

        if (!foundResponseHeaders && serverData.length > 1) {
            const combined = concatenate(serverData);
            try {
                const frames = parseFrames(combined);
                // Reset decoder and process fresh - combined data is a new sequence
                responseHpack.reset();
                parsedResponse = processFrames(frames, streamId, responseHpack, false);
                if (parsedResponse) {
                    foundResponseHeaders = true;
                    if (verbose) console.log(`  Found response (combined): ${parsedResponse.status}`);
                }
            } catch (e) {
                if (verbose) console.log(`  Combined server parse error: ${e.message}`);
            }
        }

        return { parsedRequest, parsedResponse, foundRequestHeaders, foundResponseHeaders };
    }

}
