/**
 * HTTP/3 Validator
 * Validates HTTP/3 transactions using forensic evidence
 *
 * SECURITY MODEL: "Extract Everything, Trust Nothing"
 * =================================================
 * See http2.js for detailed documentation.
 *
 * Key points:
 * - EXTRACTED values → security decisions (CertificateVerify, chain validation)
 * - CLAIMED values → hash comparison only
 * - Resumed sessions → re-validate original_handshake
 * - QUIC extraction handled by quic-extractor.js
 */

import { BaseValidator } from './base-validator.js';
import { Http3Reconstructor } from '../reconstruction/http3.js';
import {
    findDifferences,
    normalizeForValidation,
    hashTransaction
} from '../utils/helpers.js';
import { validateCertificateChain } from '../certificate/chain-validator.js';

export class Http3Validator extends BaseValidator {
    constructor(options = {}) {
        super(options);
        this.reconstructor = options.reconstructor || new Http3Reconstructor(options);
    }

    /**
     * Validate HTTP/3 transaction
     * @param {Object} evidence - Forensic evidence (for cryptographic work)
     * @param {Object} claimed - Claimed data (for final hash comparison only)
     * @returns {Promise<ValidationResult>}
     */
    async validate(evidence, claimed) {
        const result = this.createResult();
        const { verbose = false } = this.options;

        // Use reconstructor to handle all decryption, parsing, and certificate extraction
        const { reconstructed, error, certificateVerifyResult } = await this.reconstructor.reconstruct(claimed, evidence);

        if (error) {
            // Set appropriate validation level based on error type
            if (error.includes('decryption') || error.includes('decrypt')) {
                result.error = error;
                return result;
            } else if (error.includes('parse') || error.includes('headers')) {
                // Decryption succeeded but parsing failed
                result.level = 'decrypt';
                result.valid = true;
                result.error = error;
                return result;
            } else {
                result.error = error;
                return result;
            }
        }

        // Decryption and parsing succeeded
        result.level = 'parse';
        result.valid = true;

        // Record CertificateVerify result
        if (certificateVerifyResult) {
            result.details.certificateVerifySignature = {
                verified: certificateVerifyResult.valid,
                error: certificateVerifyResult.error,
            };

            if (verbose) {
                console.log(`  [VERIFY] CertificateVerify signature: ${certificateVerifyResult.valid ? 'VALID' : 'INVALID'}`);
                if (certificateVerifyResult.error) {
                    console.log(`  [VERIFY] Error: ${certificateVerifyResult.error}`);
                }
            }
        }

        // SECURITY: Enforce CertificateVerify - if verification was attempted and failed, reject
        if (result.details.certificateVerifySignature && !result.details.certificateVerifySignature.verified) {
            result.level = 'none';
            result.valid = false;
            result.error = `CertificateVerify signature invalid: ${result.details.certificateVerifySignature.error || 'signature mismatch'}`;
            return result;
        }

        // SECURITY: Validate certificate chain (CT lookup + chain signatures + SNI verification)
        const certChain = reconstructed?.certificate_info?.certificate_chain;
        if (certChain && certChain.length > 0) {
            const chainValidation = await validateCertificateChain(certChain, {
                sni: reconstructed.certificate_info?.sni,
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
        }

        // Hash-based comparison:
        // - Original uses CLAIMED data (what was captured)
        // - Reconstructed uses EXTRACTED data (what we decrypted from handshake)
        // If they match, the claimed data is validated as genuine
        const original = normalizeForValidation(claimed);

        const originalHash = await hashTransaction(original);
        const reconstructedHash = await hashTransaction(reconstructed);
        const match = originalHash === reconstructedHash;

        if (match) {
            result.level = 'full';
            result.details = { matched: 'hash' };
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
                if (differences.length > 10) {
                    console.log(`    ... and ${differences.length - 10} more`);
                }
            }
        }

        return result;
    }
}
