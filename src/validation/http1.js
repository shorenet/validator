/**
 * HTTP/1.x Validator
 * Validates HTTP/1 transactions using forensic evidence
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
import { Http1Reconstructor } from '../reconstruction/http1.js';
import { parseKeylog } from '../crypto/keylog-parser.js';
import { decryptTlsRecords, extractServerRandom } from '../crypto/decrypt-records.js';
import { extractWithFallback, validateOriginalHandshake } from '../certificate/tls-extractor.js';
import { findDifferences, hashTransaction } from '../utils/helpers.js';
import { extractHandshakeMetadata, computeTranscriptHash, verifyCertificateVerifySignature, verifyServerKeyExchangeSignature } from '../certificate/handshake-metadata-extractor.js';
import { validateCertificateChain } from '../certificate/chain-validator.js';

export class Http1Validator extends BaseValidator {
    constructor(options = {}) {
        super(options);
        this.reconstructor = options.reconstructor || new Http1Reconstructor(options);
    }

    /**
     * Validate HTTP/1 transaction
     * @param {Object} evidence - Forensic evidence (for cryptographic work)
     * @param {Object} claimed - Claimed data (for final hash comparison only)
     * @param {Object} options - Optional legacy functions {decryptTlsStream}
     * @returns {Promise<ValidationResult>}
     */
    async validate(evidence, claimed, options = {}) {
        const result = this.createResult();
        const { verbose = false } = this.options;

        // Legacy decryptTlsStream can be passed in for backward compatibility
        const { decryptTlsStream } = options;

        const keylog = parseKeylog(evidence.keylog);
        if (!keylog) {
            result.error = 'Invalid keylog';
            return result;
        }

        // For TLS 1.2, use server_random from evidence (extracted at capture time)
        // Fallback to extracting from raw_packets for backwards compatibility
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

        // Detect new vs old format
        const hasNewFormat = evidence.tls_records && evidence.tls_records.length > 0;
        let allPlaintext, error;

        if (hasNewFormat) {
            // NEW ARCHITECTURE: Direct TLS record decryption
            if (verbose) {
                console.log('  Using new TLS record-based architecture');
            }
            const decryptResult = await decryptTlsRecords(evidence.tls_records, keylog, this.options);
            error = decryptResult.error;
            allPlaintext = decryptResult.plaintext;
            if (decryptResult.handshakePlaintext) {
                evidence._handshakePlaintext = decryptResult.handshakePlaintext;
            }
        } else if (decryptTlsStream) {
            // LEGACY ARCHITECTURE: TCP packet-based (requires decryptTlsStream to be passed)
            if (verbose) {
                console.log('  Using legacy packet-based architecture');
            }
            const decryptResult = await decryptTlsStream(evidence, keylog, this.options);
            error = decryptResult.error;
            allPlaintext = decryptResult.plaintext;
        } else {
            result.error = 'No tls_records in evidence and legacy decryptTlsStream not provided';
            return result;
        }

        if (error) {
            result.error = error;
            return result;
        }

        if (allPlaintext.length === 0) {
            result.error = 'Decryption failed';
            return result;
        }

        result.level = 'decrypt';
        result.valid = true;

        // Reconstruct transaction from plaintext
        const { reconstructed, error: reconstructError } = await this.reconstructor.reconstruct(claimed, evidence, allPlaintext);

        if (reconstructError) {
            result.error = reconstructError;
            return result;
        }

        if (!reconstructed) {
            result.error = 'Reconstruction failed';
            return result;
        }

        result.level = 'parse';

        // Extract certificates
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

        // Add EXTRACTED certificates and metadata to reconstructed transaction
        // NOTE: Do NOT copy from claimed data — only use what was extracted from the handshake.
        reconstructed.certificate_info = extractedCertInfo;

        // Build normalized original using CLAIMED data
        // Include all fields that buildNormalizedTransaction includes for reconstructed
        const original = {
            id: claimed.id,
            protocol: claimed.protocol,
            connection: claimed.connection ? {
                id: claimed.connection.id,
                client_addr: claimed.connection.client_addr,
                server_addr: claimed.connection.server_addr,
            } : null,
            request: {
                method: claimed.request.method,
                url: claimed.request.url,
                headers: claimed.request.headers
            }
        };

        if (claimed.response) {
            original.response = {
                status: claimed.response.status,
                headers: claimed.response.headers
            };
        }

        // Use CLAIMED TLS info for original (what was captured)
        // Backward compat: fall back to evidence.certificate_info for old data
        const claimedCertInfo = claimed.tls || evidence.certificate_info || null;
        if (claimedCertInfo) {
            original.certificate_info = claimedCertInfo;
        }

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
                differences,
            };

            if (verbose) {
                console.log(`  Original hash:      ${originalHash}`);
                console.log(`  Reconstructed hash: ${reconstructedHash}`);
                console.log(`  Differences (${differences.length}):`);
                for (const diff of differences.slice(0, 10)) {
                    console.log(`    ${diff}`);
                }
                if (differences.length > 10) {
                    console.log(`    ... and ${differences.length - 10} more`);
                }
            }
        }

        return result;
    }
}
