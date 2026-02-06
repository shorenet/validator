/**
 * Validator UI Module
 * Handles DOM manipulation and UI updates for the validator browser app
 */

export class ValidatorUI {
    /**
     * Create a new ValidatorUI instance
     * @param {string} containerId - DOM element ID for the validator container
     */
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        if (!this.container) {
            throw new Error(`Container element #${containerId} not found`);
        }
        this.injectStyles();
    }

    /**
     * Inject CSS styles for the validator UI
     */
    injectStyles() {
        if (document.getElementById('validator-ui-styles')) return;

        const style = document.createElement('style');
        style.id = 'validator-ui-styles';
        style.textContent = `
            .validation-result {
                border: 1px solid #ddd;
                border-radius: 8px;
                margin: 8px 0;
                padding: 12px;
                background: #fff;
            }
            .validation-result.valid { border-left: 4px solid #28a745; }
            .validation-result.invalid { border-left: 4px solid #dc3545; }

            .result-header {
                display: flex;
                align-items: center;
                gap: 12px;
                margin-bottom: 8px;
            }
            .result-index { color: #666; font-size: 0.9em; }
            .result-status {
                padding: 2px 8px;
                border-radius: 4px;
                font-size: 0.85em;
                font-weight: 500;
            }
            .valid .result-status { background: #d4edda; color: #155724; }
            .invalid .result-status { background: #f8d7da; color: #721c24; }
            .result-valid { font-size: 1.2em; }

            .result-error {
                background: #f8d7da;
                color: #721c24;
                padding: 8px;
                border-radius: 4px;
                margin: 8px 0;
                font-size: 0.9em;
            }

            .result-details { margin-top: 12px; }

            .details-section {
                background: #f8f9fa;
                border-radius: 6px;
                padding: 10px;
                margin: 8px 0;
            }
            .section-title {
                font-weight: 600;
                margin-bottom: 8px;
                font-size: 0.95em;
            }

            .proof-item, .hash-item {
                display: flex;
                align-items: center;
                gap: 8px;
                padding: 4px 0;
            }
            .proof-item.verified, .hash-item.match { color: #155724; }
            .proof-item.failed { color: #721c24; }
            .proof-item.warning { color: #856404; }
            .hash-item.mismatch { color: #721c24; }

            .proof-icon, .hash-icon { font-size: 1.1em; }
            .proof-label, .hash-label { font-weight: 500; min-width: 140px; }
            .proof-status, .hash-status { font-size: 0.9em; }

            .hash-value {
                display: flex;
                align-items: center;
                gap: 8px;
                padding: 2px 0;
                font-size: 0.85em;
            }
            .hash-value code {
                background: #e9ecef;
                padding: 2px 6px;
                border-radius: 3px;
                font-family: monospace;
            }

            .differences-list {
                margin: 0;
                padding-left: 20px;
                font-size: 0.9em;
            }
            .differences-list li { margin: 4px 0; }
            .differences-list .more { color: #666; font-style: italic; }

            .other-detail {
                font-size: 0.85em;
                padding: 2px 0;
            }

            .stats-container {
                display: flex;
                flex-wrap: wrap;
                gap: 16px;
                padding: 12px;
                background: #f8f9fa;
                border-radius: 8px;
                margin: 12px 0;
            }
            .stat {
                display: flex;
                gap: 8px;
            }
            .stat-label { font-weight: 500; }
            .stat-value { font-weight: 600; }

            .progress-bar {
                height: 24px;
                background: #007bff;
                color: white;
                text-align: center;
                line-height: 24px;
                border-radius: 4px;
                transition: width 0.3s ease;
            }

            .error-message {
                background: #f8d7da;
                color: #721c24;
                padding: 12px;
                border-radius: 8px;
                margin: 12px 0;
            }

            .drop-zone {
                border: 2px dashed #ccc;
                border-radius: 8px;
                padding: 40px;
                text-align: center;
                cursor: pointer;
                transition: all 0.2s ease;
            }
            .drop-zone.drag-over {
                border-color: #007bff;
                background: #e7f1ff;
            }
        `;
        document.head.appendChild(style);
    }

    /**
     * Show progress message during validation
     * @param {string} message - Progress message
     * @param {number} current - Current transaction number
     * @param {number} total - Total transactions
     */
    showProgress(message, current, total) {
        const percentage = total > 0 ? Math.round((current / total) * 100) : 0;
        console.log(`[${percentage}%] ${message} (${current}/${total})`);

        // Update progress bar if exists
        const progressBar = this.container.querySelector('.progress-bar');
        if (progressBar) {
            progressBar.style.width = `${percentage}%`;
            progressBar.textContent = `${percentage}%`;
        }

        // Update status text
        const statusText = this.container.querySelector('.status-text');
        if (statusText) {
            statusText.textContent = message;
        }
    }

    /**
     * Show validation result
     * @param {Object} result - Validation result
     * @param {number} index - Transaction index
     */
    showResult(result, index) {
        const resultDiv = document.createElement('div');
        resultDiv.className = `validation-result ${result.valid ? 'valid' : 'invalid'}`;
        resultDiv.innerHTML = `
            <div class="result-header">
                <span class="result-index">#${index + 1}</span>
                <span class="result-status">${result.level || 'failed'}</span>
                <span class="result-valid">${result.valid ? '✓' : '✗'}</span>
            </div>
            ${result.error ? `<div class="result-error">${result.error}</div>` : ''}
            ${this.renderResultDetails(result.details)}
        `;

        const resultsContainer = this.container.querySelector('.results-container');
        if (resultsContainer) {
            resultsContainer.appendChild(resultDiv);
        }
    }

    /**
     * Render result details with enhanced proof and hash display
     * @param {Object} details - Result details
     * @returns {string} HTML string
     */
    renderResultDetails(details) {
        if (!details || Object.keys(details).length === 0) {
            return '';
        }

        const sections = [];

        // Security Proofs Section
        const proofs = [];

        // CertificateVerify signature (TLS 1.3)
        if (details.certificateVerifySignature) {
            const cv = details.certificateVerifySignature;
            proofs.push(`
                <div class="proof-item ${cv.verified ? 'verified' : 'failed'}">
                    <span class="proof-icon">${cv.verified ? '🔐' : '⚠️'}</span>
                    <span class="proof-label">CertificateVerify:</span>
                    <span class="proof-status">${cv.verified ? 'Verified' : cv.error || 'Failed'}</span>
                </div>
            `);
        }

        // ServerKeyExchange signature (TLS 1.2)
        if (details.serverKeyExchangeSignature) {
            const ske = details.serverKeyExchangeSignature;
            proofs.push(`
                <div class="proof-item ${ske.verified ? 'verified' : 'failed'}">
                    <span class="proof-icon">${ske.verified ? '🔐' : '⚠️'}</span>
                    <span class="proof-label">ServerKeyExchange:</span>
                    <span class="proof-status">${ske.verified ? 'Verified' : ske.error || 'Failed'}</span>
                </div>
            `);
        }

        // Chain Validation
        if (details.chainValidation) {
            const chain = details.chainValidation;
            proofs.push(`
                <div class="proof-item ${chain.valid ? 'verified' : 'warning'}">
                    <span class="proof-icon">${chain.valid ? '📜' : '⚠️'}</span>
                    <span class="proof-label">Chain Validation:</span>
                    <span class="proof-status">
                        ${chain.chainSignaturesValid ? '✓ Signatures' : '✗ Signatures'}
                        ${chain.sniVerified ? '✓ SNI' : '✗ SNI'}
                        ${chain.ctFound ? '✓ CT' : '○ CT'}
                    </span>
                </div>
            `);
        }

        if (proofs.length > 0) {
            sections.push(`
                <div class="details-section proofs-section">
                    <div class="section-title">🔒 Security Proofs</div>
                    ${proofs.join('')}
                </div>
            `);
        }

        // Hashes Section
        if (details.originalHash || details.reconstructedHash || details.matched) {
            const hashMatch = details.matched || details.originalHash === details.reconstructedHash;
            sections.push(`
                <div class="details-section hashes-section">
                    <div class="section-title">🔢 Transaction Hashes</div>
                    <div class="hash-item ${hashMatch ? 'match' : 'mismatch'}">
                        <span class="hash-icon">${hashMatch ? '✓' : '✗'}</span>
                        <span class="hash-label">Match:</span>
                        <span class="hash-status">${hashMatch ? 'Hashes match' : 'Hashes differ'}</span>
                    </div>
                    ${details.originalHash ? `
                        <div class="hash-value">
                            <span class="hash-label">Original:</span>
                            <code>${this.escapeHtml(details.originalHash.substring(0, 16))}...</code>
                        </div>
                    ` : ''}
                    ${details.reconstructedHash ? `
                        <div class="hash-value">
                            <span class="hash-label">Reconstructed:</span>
                            <code>${this.escapeHtml(details.reconstructedHash.substring(0, 16))}...</code>
                        </div>
                    ` : ''}
                </div>
            `);
        }

        // Differences Section (if any)
        if (details.differences && Array.isArray(details.differences) && details.differences.length > 0) {
            sections.push(`
                <div class="details-section differences-section">
                    <div class="section-title">⚡ Differences (${details.differences.length})</div>
                    <ul class="differences-list">
                        ${details.differences.slice(0, 5).map(diff => `<li>${this.escapeHtml(diff)}</li>`).join('')}
                        ${details.differences.length > 5 ? `<li class="more">... and ${details.differences.length - 5} more</li>` : ''}
                    </ul>
                </div>
            `);
        }

        // Other Details (catch-all for any unhandled fields)
        const handledKeys = ['certificateVerifySignature', 'serverKeyExchangeSignature',
                            'chainValidation', 'originalHash', 'reconstructedHash',
                            'matched', 'differences', 'parsedRequest', 'parsedResponse'];
        const otherDetails = Object.entries(details)
            .filter(([key]) => !handledKeys.includes(key))
            .map(([key, value]) => {
                const displayValue = typeof value === 'object'
                    ? JSON.stringify(value).substring(0, 100)
                    : String(value).substring(0, 100);
                return `<div class="other-detail"><strong>${key}:</strong> ${this.escapeHtml(displayValue)}</div>`;
            });

        if (otherDetails.length > 0) {
            sections.push(`
                <div class="details-section other-section">
                    <div class="section-title">📋 Other Details</div>
                    ${otherDetails.join('')}
                </div>
            `);
        }

        return sections.length > 0 ? `<div class="result-details">${sections.join('')}</div>` : '';
    }

    /**
     * Show error message
     * @param {Error|string} error - Error to display
     */
    showError(error) {
        const errorMessage = error instanceof Error ? error.message : error;
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.innerHTML = `
            <strong>Error:</strong> ${this.escapeHtml(errorMessage)}
        `;
        this.container.appendChild(errorDiv);
    }

    /**
     * Update validation statistics
     * @param {Object} stats - Statistics object
     */
    updateStats(stats) {
        const statsContainer = this.container.querySelector('.stats-container');
        if (!statsContainer) return;

        statsContainer.innerHTML = `
            <div class="stat">
                <span class="stat-label">Total:</span>
                <span class="stat-value">${stats.total || 0}</span>
            </div>
            <div class="stat">
                <span class="stat-label">Valid:</span>
                <span class="stat-value">${stats.valid || 0}</span>
            </div>
            <div class="stat">
                <span class="stat-label">Full:</span>
                <span class="stat-value">${stats.full || 0}</span>
            </div>
            <div class="stat">
                <span class="stat-label">Parse:</span>
                <span class="stat-value">${stats.parse || 0}</span>
            </div>
            <div class="stat">
                <span class="stat-label">Decrypt:</span>
                <span class="stat-value">${stats.decrypt || 0}</span>
            </div>
            <div class="stat">
                <span class="stat-label">Failed:</span>
                <span class="stat-value">${stats.failed || 0}</span>
            </div>
        `;
    }

    /**
     * Clear all results
     */
    clearResults() {
        const resultsContainer = this.container.querySelector('.results-container');
        if (resultsContainer) {
            resultsContainer.innerHTML = '';
        }

        const errorMessages = this.container.querySelectorAll('.error-message');
        errorMessages.forEach(el => el.remove());
    }

    /**
     * Escape HTML to prevent XSS
     * @param {string} text - Text to escape
     * @returns {string} Escaped text
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}
