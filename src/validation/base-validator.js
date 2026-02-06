/**
 * Base class for protocol validators
 * Provides common validation patterns and error handling
 */

import { ValidationResult } from './result.js';

export class BaseValidator {
    constructor(options = {}) {
        this.options = options;
    }

    /**
     * Validate a transaction against forensic evidence
     * @param {Object} evidence - Forensic evidence (keylog, packets, etc.) — used for cryptographic work
     * @param {Object} claimed - Claimed data (id, protocol, request, response, tls, etc.) — used only for final hash comparison
     * @returns {Promise<ValidationResult>}
     */
    async validate(evidence, claimed) {
        throw new Error('Subclass must implement validate()');
    }

    /**
     * Create a validation result
     */
    createResult() {
        return new ValidationResult();
    }
}
