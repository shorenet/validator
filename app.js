/**
 * Validator Browser Application
 * Main entry point for the browser-based validator UI
 */

import { validate } from './src/index.js';
import { ValidatorUI } from './ui.js';
import { FileHandler } from './file-handler.js';

/**
 * Validator Browser App
 * Coordinates UI, file handling, and validation
 */
export class ValidatorApp {
    /**
     * Create a new ValidatorApp instance
     * @param {Object} options - Application options
     */
    constructor(options = {}) {
        this.options = {
            containerId: options.containerId || 'validator-container',
            batchSize: options.batchSize || 100,
            verbose: options.verbose || false,
        };

        this.ui = new ValidatorUI(this.options.containerId);
        this.fileHandler = new FileHandler();
        this.isValidating = false;
        this.stats = {
            total: 0,
            valid: 0,
            full: 0,
            parse: 0,
            decrypt: 0,
            failed: 0,
        };
    }

    /**
     * Initialize the application
     * Sets up event listeners for file upload and drag-and-drop
     */
    async init() {
        this.setupEventListeners();
        console.log('Validator app initialized');
    }

    /**
     * Set up event listeners
     */
    setupEventListeners() {
        const container = document.getElementById(this.options.containerId);
        if (!container) {
            console.error('Container element not found');
            return;
        }

        // File input
        const fileInput = container.querySelector('input[type="file"]');
        if (fileInput) {
            fileInput.addEventListener('change', async (event) => {
                try {
                    const transactions = await this.fileHandler.handleFileSelect(event);
                    await this.validateFile(transactions);
                } catch (error) {
                    this.ui.showError(error);
                }
            });
        }

        // Drag and drop
        const dropZone = container.querySelector('.drop-zone');
        if (dropZone) {
            dropZone.addEventListener('dragover', (event) => {
                event.preventDefault();
                dropZone.classList.add('drag-over');
            });

            dropZone.addEventListener('dragleave', () => {
                dropZone.classList.remove('drag-over');
            });

            dropZone.addEventListener('drop', async (event) => {
                dropZone.classList.remove('drag-over');
                try {
                    const transactions = await this.fileHandler.handleDrop(event);
                    await this.validateFile(transactions);
                } catch (error) {
                    this.ui.showError(error);
                }
            });
        }

        // Clear button
        const clearButton = container.querySelector('.clear-button');
        if (clearButton) {
            clearButton.addEventListener('click', () => {
                this.ui.clearResults();
                this.resetStats();
            });
        }
    }

    /**
     * Validate a file's transactions
     * @param {Array<Object>} transactions - Array of transaction wrappers
     */
    async validateFile(transactions) {
        if (this.isValidating) {
            this.ui.showError('Validation already in progress');
            return;
        }

        this.isValidating = true;
        this.ui.clearResults();
        this.resetStats();

        try {
            const total = transactions.length;
            this.stats.total = total;

            for (let i = 0; i < total; i++) {
                const record = transactions[i];
                const tx = record.data || record;
                const type = record.type;

                // Show progress
                if (i % 10 === 0 || i === total - 1) {
                    this.ui.showProgress(
                        `Validating transaction ${i + 1}/${total}`,
                        i + 1,
                        total
                    );
                }

                // Validate transaction
                try {
                    const evidence = tx.forensic_evidence;
                    if (!evidence) {
                        this.stats.failed++;
                        continue;
                    }

                    // Use the validate function from src/index.js
                    const result = await validate(record, {
                        verbose: this.options.verbose,
                        skipCtLookup: true, // Skip CT lookup in browser (network dependent)
                    });

                    // Update stats
                    if (result.valid) {
                        this.stats.valid++;
                        if (result.level === 'full') this.stats.full++;
                        else if (result.level === 'parse') this.stats.parse++;
                        else if (result.level === 'decrypt') this.stats.decrypt++;
                    } else {
                        this.stats.failed++;
                    }

                    // Show result in UI (only for first 100 to avoid DOM overload)
                    if (i < 100) {
                        this.ui.showResult(result, i);
                    }
                } catch (error) {
                    console.error(`Error validating transaction ${i + 1}:`, error);
                    this.stats.failed++;
                }

                // Update stats display
                if (i % 10 === 0 || i === total - 1) {
                    this.ui.updateStats(this.stats);
                }

                // Yield to browser to keep UI responsive
                if (i % this.options.batchSize === 0) {
                    await this.sleep(0);
                }
            }

            // Final update
            this.ui.showProgress(`Validation complete`, total, total);
            this.ui.updateStats(this.stats);
            console.log('Validation complete:', this.stats);
        } catch (error) {
            this.ui.showError(error);
            console.error('Validation error:', error);
        } finally {
            this.isValidating = false;
        }
    }

    /**
     * Reset statistics
     */
    resetStats() {
        this.stats = {
            total: 0,
            valid: 0,
            full: 0,
            parse: 0,
            decrypt: 0,
            failed: 0,
        };
        this.ui.updateStats(this.stats);
    }

    /**
     * Sleep for specified milliseconds (for yielding to browser)
     * @param {number} ms - Milliseconds to sleep
     * @returns {Promise<void>}
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// ============================================================================
// Browser Entry Point
// ============================================================================

/**
 * Initialize the validator app when DOM is ready
 */
if (typeof window !== 'undefined') {
    window.addEventListener('DOMContentLoaded', () => {
        // Create and initialize the app
        const app = new ValidatorApp({
            containerId: 'validator-container',
            verbose: false,
        });

        app.init().catch(error => {
            console.error('Failed to initialize validator app:', error);
        });

        // Expose app globally for debugging
        window.validatorApp = app;
    });
}
