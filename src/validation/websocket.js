/**
 * WebSocket Validator
 * Validates WebSocket messages using cryptographic proof from TLS records.
 *
 * Proof model:
 * - TLS records contain encrypted WebSocket frames
 * - Decryption with keylog produces the wire-format frames
 * - For compressed messages, context-aware decompression rebuilds deflate state
 * - Hash comparison verifies claimed content matches decrypted content
 *
 * SECURITY MODEL: "Extract Everything, Trust Nothing"
 * =================================================
 * See http2.js for detailed documentation.
 *
 * Key points:
 * - EXTRACTED values → security decisions (CertificateVerify, chain validation)
 * - CLAIMED values → hash comparison only
 * - Resumed sessions → re-validate original_handshake
 * - Ticket binding verified in extractWithFallback()
 */

import { BaseValidator } from './base-validator.js';
import { WebSocketReconstructor } from '../reconstruction/websocket.js';
import { parseKeylog } from '../crypto/keylog-parser.js';
import { decryptTlsRecords, extractServerRandom } from '../crypto/decrypt-records.js';
import { extractWithFallback, validateOriginalHandshake } from '../certificate/tls-extractor.js';
import { extractHandshakeMetadata, computeTranscriptHash, verifyCertificateVerifySignature, verifyServerKeyExchangeSignature } from '../certificate/handshake-metadata-extractor.js';
import { validateCertificateChain } from '../certificate/chain-validator.js';
import {
    findDifferences,
    hashTransaction,
    concatenate,
    normalizeForValidation
} from '../utils/helpers.js';
import { parseFrames as parseWsFrames, OPCODE, WebSocketDeflateContext } from '../protocol/websocket/frame-parser.js';

export class WebSocketValidator extends BaseValidator {
    constructor(options = {}) {
        super(options);
        this.reconstructor = options.reconstructor || new WebSocketReconstructor(options);
    }

    /**
     * Validate WebSocket message using TLS record-based cryptographic proof.
     *
     * @param {Object} evidence - Forensic evidence (tls_records, keylog, etc.) — for cryptographic work
     * @param {Object} claimed - Claimed message data (for final hash comparison only)
     * @returns {Promise<ValidationResult>}
     */
    async validate(evidence, claimed) {
        const result = this.createResult();
        const { verbose = false } = this.options;

        // Require TLS records (new architecture only)
        if (!evidence.tls_records || evidence.tls_records.length === 0) {
            result.error = 'Missing tls_records in evidence';
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

        // Decrypt TLS records
        if (verbose) console.log(`  Decrypting ${evidence.tls_records.length} TLS records`);
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

        // Filter plaintext by direction
        const isFromClient = claimed.direction === 'ClientToServer' || claimed.direction === 'client_to_server';
        const directionFilter = isFromClient ? 'client' : 'server';

        const dirPlaintext = allPlaintext.filter(p => p.direction === directionFilter);
        if (dirPlaintext.length === 0) {
            result.details = { note: 'No plaintext in expected direction' };
            return result;
        }

        // Concatenate all plaintext for this direction
        const combined = concatenate(dirPlaintext.map(p => p.data));

        // Skip HTTP upgrade headers if present
        let wsDataStart = 0;
        const httpEnd = this.findHttpEnd(combined);
        if (httpEnd !== -1) {
            wsDataStart = httpEnd;
            if (verbose) console.log(`  HTTP headers end at byte ${httpEnd}`);
        }

        const wsData = combined.slice(wsDataStart);
        if (wsData.length === 0) {
            result.details = { note: 'No WebSocket data after HTTP headers' };
            return result;
        }

        // Parse WebSocket frames
        let wsFrames;
        try {
            wsFrames = parseWsFrames(wsData);
        } catch (e) {
            result.details = { note: `WebSocket frame parsing error: ${e.message}` };
            return result;
        }

        if (wsFrames.length === 0) {
            result.details = { note: 'No WebSocket frames found' };
            return result;
        }

        result.level = 'parse';

        // Always use async streaming decompression for compressed frames.
        // The sync inflateRawSync doesn't flush properly and fails on many payloads.
        // The streaming approach with explicit flush works reliably.
        const hasCompressedFrames = wsFrames.some(f => f.compressedPayload);
        if (hasCompressedFrames) {
            if (verbose) {
                console.log('  Using async streaming decompression for compressed frames');
                if (evidence.compression_requires_context) {
                    console.log('  Context takeover enabled - maintaining deflate state');
                }
            }

            // Create stateful decompressor
            const deflateContext = new WebSocketDeflateContext();

            // Re-decompress all compressed frames in order
            for (const frame of wsFrames) {
                if (frame.compressedPayload) {
                    try {
                        const decompressed = await deflateContext.decompress(frame.compressedPayload);
                        // Update the frame's payload with correctly decompressed data
                        frame.payload = decompressed;
                        if (verbose) {
                            console.log(`  [Deflate] Frame decompressed: ${frame.compressedPayload.length} -> ${decompressed.length} bytes`);
                        }
                    } catch (e) {
                        if (verbose) {
                            console.log(`  [Deflate] Decompression error: ${e.message}`);
                        }
                        // Keep original payload from stateless decompression attempt
                    }

                    // Reset context if no_context_takeover is set
                    if (!evidence.compression_requires_context) {
                        deflateContext.reset();
                    }
                }
            }
        }

        // Map message type to expected opcode
        const opcodeMap = {
            'Text': OPCODE.TEXT,
            'Binary': OPCODE.BINARY,
            'Ping': OPCODE.PING,
            'Pong': OPCODE.PONG,
            'Close': OPCODE.CLOSE
        };
        const expectedOpcode = opcodeMap[claimed.message_type] || OPCODE.TEXT;

        // Find frames matching the expected opcode
        const matchingFrames = wsFrames.filter(f => f.opcode === expectedOpcode);

        if (matchingFrames.length === 0) {
            result.details = { note: `No ${claimed.message_type} frames found` };
            return result;
        }

        // Extract certificates from TLS handshake
        const extractedCerts = await extractWithFallback(evidence, keylog, this.options);

        if (!extractedCerts.chain) {
            result.error = `Certificate extraction failed: ${extractedCerts.error || 'unknown'}`;
            result.details = { note: 'Evidence bundle missing encrypted handshake packets with Certificate message' };
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

        // Build certificate info for reconstructed using EXTRACTED certs + EXTRACTED metadata
        const extractedCertInfo = {
            certificate_chain: extractedCerts.chain,
        };

        // Use extracted metadata if available
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

        // NOTE: Do NOT copy from claimed into extracted - that would negate validation.
        // If extracted is missing fields, they stay missing. The hash comparison will
        // detect mismatches between claimed (original) and extracted (reconstructed).

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
            evidenceTimestamp: claimed.timestamp_us,
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

        // Reconstruct message from parsed frames (all content from TLS records)
        // Uses EXTRACTED certs from decrypted handshake
        const reconstructed = this.reconstructor.reconstruct(claimed, extractedCertInfo, matchingFrames);
        if (!reconstructed) {
            result.details = { note: 'Could not reconstruct message' };
            return result;
        }

        // Normalize original message using CLAIMED data (what was captured)
        // If they match, the claimed data is validated as genuine
        const original = normalizeForValidation(claimed);

        // Compare via hash
        const originalHash = await hashTransaction(original);
        const reconstructedHash = await hashTransaction(reconstructed);
        const match = originalHash === reconstructedHash;

        if (match) {
            result.level = 'full';
            result.details = { matched: 'hash' };
        } else {
            const differences = findDifferences(original, reconstructed);

            result.details = {
                originalHash,
                reconstructedHash,
                framesFound: matchingFrames.length,
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

        return result;
    }

    /**
     * Find end of HTTP headers in combined data
     */
    findHttpEnd(data) {
        for (let i = 0; i < data.length - 3; i++) {
            if (data[i] === 0x0d && data[i + 1] === 0x0a &&
                data[i + 2] === 0x0d && data[i + 3] === 0x0a) {
                return i + 4;
            }
        }
        return -1;
    }

}
