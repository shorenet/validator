/**
 * HTTP/1.x Transaction Reconstructor
 * Reconstructs HTTP/1 transactions from decrypted plaintext
 */

import { concatenate } from '../utils/helpers.js';
import { buildNormalizedTransaction } from './shared.js';

export class Http1Reconstructor {
    constructor(options = {}) {
        this.options = options;
    }

    /**
     * Reconstruct HTTP/1 transaction from decrypted plaintext
     * @param {Object} claimed - Claimed transaction data (for identity fields)
     * @param {Object} evidence - Forensic evidence (unused here, kept for interface consistency)
     * @param {Array} allPlaintext - Decrypted plaintext segments
     * @returns {{reconstructed: Object|null, error: string|null}}
     */
    async reconstruct(claimed, evidence, allPlaintext) {
        const { verbose = false } = this.options;

        // Combine client plaintext
        const clientPlaintext = allPlaintext.filter(p => p.direction === 'client');
        if (clientPlaintext.length === 0) {
            return { reconstructed: null, error: 'No client data' };
        }

        const combined = concatenate(clientPlaintext.map(p => p.data));
        const text = new TextDecoder().decode(combined);
        const lines = text.split('\r\n');

        if (lines.length === 0) {
            return { reconstructed: null, error: 'Empty request' };
        }

        // Parse request line
        const requestLine = lines[0];
        const match = requestLine.match(/^(\w+)\s+(\S+)\s+HTTP\/([\d.]+)/);
        if (!match) {
            return { reconstructed: null, error: 'Invalid request line' };
        }

        const method = match[1];
        const path = match[2];
        const version = match[3];

        // Parse headers
        const headers = {};
        let i = 1;
        while (i < lines.length && lines[i] !== '') {
            const headerLine = lines[i];
            const colonIdx = headerLine.indexOf(':');
            if (colonIdx > 0) {
                // Preserve original header name case for exact comparison
                // HTTP/1.1 headers are case-insensitive per spec, but we need
                // exact match for forensic validation (wire format → captured format)
                const name = headerLine.substring(0, colonIdx);
                const value = headerLine.substring(colonIdx + 1).trim();
                headers[name] = value;
            }
            i++;
        }

        // Parse response if available
        let parsedResponse = null;
        const serverPlaintext = allPlaintext.filter(p => p.direction === 'server');
        if (serverPlaintext.length > 0) {
            const serverCombined = concatenate(serverPlaintext.map(p => p.data));
            const serverText = new TextDecoder().decode(serverCombined);
            const serverLines = serverText.split('\r\n');

            if (serverLines.length > 0) {
                const statusMatch = serverLines[0].match(/^HTTP\/([\d.]+)\s+(\d+)\s*(.*)/);
                if (statusMatch) {
                    const respHeaders = {};
                    let j = 1;
                    while (j < serverLines.length && serverLines[j] !== '') {
                        const headerLine = serverLines[j];
                        const colonIdx = headerLine.indexOf(':');
                        if (colonIdx > 0) {
                            // Preserve original header name case (same as request headers)
                            const name = headerLine.substring(0, colonIdx);
                            const value = headerLine.substring(colonIdx + 1).trim();
                            respHeaders[name] = value;
                        }
                        j++;
                    }
                    parsedResponse = {
                        status: parseInt(statusMatch[2], 10),
                        statusText: statusMatch[3] || '',
                        version: statusMatch[1],
                        headers: respHeaders
                    };
                }
            }
        }

        const parsedRequest = {
            method,
            path,
            version,
            authority: headers['host'] || '',
            headers
        };

        // Pass null for extractedCertInfo — the validator adds it after extraction
        const reconstructed = buildNormalizedTransaction(claimed, null, parsedRequest, parsedResponse);
        return { reconstructed, error: null };
    }

}
