/**
 * Transaction Hasher
 * Canonical hashing of transactions for comparison
 */

import { sha256, bytesToHex } from '../crypto/hash.js';

/**
 * Stable JSON stringifier that sorts object keys
 * Ensures consistent hashing regardless of property insertion order
 */
export function stableStringify(obj) {
    if (obj === null || obj === undefined) {
        return JSON.stringify(obj);
    }
    if (typeof obj !== 'object') {
        return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
        return '[' + obj.map(item => stableStringify(item)).join(',') + ']';
    }
    const keys = Object.keys(obj).sort();
    const pairs = keys.map(key => {
        const value = stableStringify(obj[key]);
        return JSON.stringify(key) + ':' + value;
    });
    return '{' + pairs.join(',') + '}';
}

/**
 * Compute SHA-256 hash of a transaction object using stable stringify
 * @param {Object} tx - Transaction object
 * @returns {Promise<string>} Hex hash string
 */
export async function hashTransaction(tx) {
    const json = stableStringify(tx);
    const bytes = new TextEncoder().encode(json);
    const hash = await sha256(bytes);
    return bytesToHex(hash);
}

/**
 * Transaction Hasher Class
 * Provides canonical hashing for transaction comparison
 */
export class TransactionHasher {
    /**
     * Hash a request object
     * @param {Object} request - Request object
     * @returns {Promise<string>} Hex hash string
     */
    async hashRequest(request) {
        if (!request) return null;
        const json = stableStringify(request);
        const bytes = new TextEncoder().encode(json);
        const hash = await sha256(bytes);
        return bytesToHex(hash);
    }

    /**
     * Hash a response object
     * @param {Object} response - Response object
     * @returns {Promise<string>} Hex hash string
     */
    async hashResponse(response) {
        if (!response) return null;
        const json = stableStringify(response);
        const bytes = new TextEncoder().encode(json);
        const hash = await sha256(bytes);
        return bytesToHex(hash);
    }

    /**
     * Hash a complete transaction
     * @param {Object} transaction - Transaction object
     * @returns {Promise<{request: string|null, response: string|null, full: string}>}
     */
    async hashTransaction(transaction) {
        return {
            request: await this.hashRequest(transaction.request),
            response: await this.hashResponse(transaction.response),
            full: await hashTransaction(transaction),
        };
    }
}
