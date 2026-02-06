/**
 * Transaction Comparator
 * Deep comparison of transactions with detailed diff output
 */

import { hashTransaction } from './hasher.js';

/**
 * Find differences between two objects recursively
 * Returns an array of difference descriptions
 *
 * @param {*} obj1 - Original object
 * @param {*} obj2 - Reconstructed object
 * @param {string} path - Current path in object tree
 * @returns {Array<string>} Array of difference descriptions
 */
export function findDifferences(obj1, obj2, path = '') {
    const diffs = [];

    // Both null/undefined = no diff
    if (obj1 == null && obj2 == null) return diffs;

    // One null, other not = diff
    if (obj1 == null) {
        diffs.push(`${path || 'root'}: original is null, reconstructed is ${JSON.stringify(obj2)}`);
        return diffs;
    }
    if (obj2 == null) {
        diffs.push(`${path || 'root'}: original is ${JSON.stringify(obj1)}, reconstructed is null`);
        return diffs;
    }

    // Different types = diff
    if (typeof obj1 !== typeof obj2) {
        diffs.push(`${path || 'root'}: type mismatch (${typeof obj1} vs ${typeof obj2})`);
        return diffs;
    }

    // Primitives - direct compare
    if (typeof obj1 !== 'object') {
        if (obj1 !== obj2) {
            diffs.push(`${path || 'root'}: ${JSON.stringify(obj1)} !== ${JSON.stringify(obj2)}`);
        }
        return diffs;
    }

    // Arrays
    if (Array.isArray(obj1) && Array.isArray(obj2)) {
        if (obj1.length !== obj2.length) {
            diffs.push(`${path || 'root'}: array length mismatch (${obj1.length} vs ${obj2.length})`);
        }
        const maxLen = Math.max(obj1.length, obj2.length);
        for (let i = 0; i < maxLen; i++) {
            diffs.push(...findDifferences(obj1[i], obj2[i], `${path}[${i}]`));
        }
        return diffs;
    }

    // Objects - compare all keys
    const keys1 = Object.keys(obj1);
    const keys2 = Object.keys(obj2);
    const allKeys = new Set([...keys1, ...keys2]);

    for (const key of allKeys) {
        const newPath = path ? `${path}.${key}` : key;
        if (!(key in obj1)) {
            diffs.push(`${newPath}: missing in original`);
        } else if (!(key in obj2)) {
            diffs.push(`${newPath}: missing in reconstructed`);
        } else {
            diffs.push(...findDifferences(obj1[key], obj2[key], newPath));
        }
    }

    return diffs;
}

/**
 * Transaction Comparator Class
 * Provides detailed comparison of transactions
 */
export class TransactionComparator {
    /**
     * Compare two transactions
     * @param {Object} original - Original transaction
     * @param {Object} reconstructed - Reconstructed transaction
     * @returns {Promise<{match: boolean, originalHash: string, reconstructedHash: string, differences: Array<string>}>}
     */
    async compare(original, reconstructed) {
        const originalHash = await hashTransaction(original);
        const reconstructedHash = await hashTransaction(reconstructed);
        const match = originalHash === reconstructedHash;

        return {
            match,
            originalHash,
            reconstructedHash,
            differences: match ? [] : findDifferences(original, reconstructed),
        };
    }

    /**
     * Check if two transactions match (hash-based)
     * @param {Object} a - First transaction
     * @param {Object} b - Second transaction
     * @returns {Promise<boolean>}
     */
    async isMatch(a, b) {
        const hashA = await hashTransaction(a);
        const hashB = await hashTransaction(b);
        return hashA === hashB;
    }

    /**
     * Compare headers specifically
     * @param {Object} headers1 - First set of headers
     * @param {Object} headers2 - Second set of headers
     * @returns {Array<string>} Array of differences
     */
    compareHeaders(headers1, headers2) {
        return findDifferences(headers1, headers2, 'headers');
    }

    /**
     * Compare body content
     * @param {string} body1 - First body
     * @param {string} body2 - Second body
     * @returns {boolean}
     */
    compareBody(body1, body2) {
        return body1 === body2;
    }
}
