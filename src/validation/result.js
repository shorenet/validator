/**
 * Validation result structure
 */
export class ValidationResult {
    constructor() {
        this.valid = false;
        this.level = 'none';  // none, decrypt, parse, full
        this.error = null;
        this.details = {};
    }
}
