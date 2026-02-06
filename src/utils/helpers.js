/**
 * Shared helper functions for validation and reconstruction
 */

import { sha256, bytesToHex } from '../crypto/hash.js';

/**
 * Concatenate arrays into a single Uint8Array
 */
export function concatenate(arrays) {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}

/**
 * Normalize headers for comparison.
 * Sorts by key to ensure consistent ordering for hash comparison.
 * @param {Object} headers - Headers object
 * @returns {Object} Sorted headers
 */
export function normalizeHeaders(headers) {
    if (!headers) return {};
    const sorted = {};
    for (const key of Object.keys(headers).sort()) {
        sorted[key] = headers[key];
    }
    return sorted;
}

/**
 * Normalize a transaction or WebSocket message for validation.
 * Strips forensic_evidence, uses certificate info from appropriate source.
 *
 * Both original and reconstructed should use this function to ensure
 * they produce identical structure for hash comparison.
 *
 * For the "original" (claimed) side: pass `claimed` with `claimed.tls` populated.
 * For the "reconstructed" (extracted) side: pass `claimed` + `extractedCertInfo`.
 *
 * @param {Object} claimed - Claimed data object (id, protocol, request, response, connection, tls, etc.)
 * @param {Object} extractedCertInfo - Certificate info with EXTRACTED chain (for reconstructed side)
 * @returns {Object} Normalized object
 */
export function normalizeForValidation(claimed, extractedCertInfo = null) {
    // For reconstructed side: use extracted cert info
    // For original (claimed) side: use claimed.tls
    // Backward compat: fall back to forensic_evidence.certificate_info for old data
    const certInfo = extractedCertInfo || claimed.tls || claimed.forensic_evidence?.certificate_info || null;

    // Normalize connection if present
    const connection = claimed.connection ? {
        id: claimed.connection.id,
        client_addr: claimed.connection.client_addr,
        server_addr: claimed.connection.server_addr,
    } : null;

    // For WebSocket messages (have message_type field)
    if (claimed.message_type) {
        const normalized = {
            id: claimed.id,
            message_type: claimed.message_type,
            direction: claimed.direction,
            payload: null,
            text: null,
            close_code: claimed.close_code || null,
            close_reason: claimed.close_reason || null,
            url: claimed.url,
            connection,
            certificate_info: certInfo,
        };

        // Set payload/text based on message type
        if (claimed.message_type === 'Text') {
            normalized.text = claimed.text || null;
        } else if (claimed.message_type === 'Binary' || claimed.message_type === 'Ping' || claimed.message_type === 'Pong') {
            normalized.payload = claimed.payload || null;
        }

        return normalized;
    }

    // For HTTP transactions
    return {
        id: claimed.id,
        protocol: claimed.protocol,
        request: claimed.request ? {
            method: claimed.request.method,
            url: claimed.request.url,
            headers: normalizeHeaders(claimed.request.headers),
        } : null,
        response: claimed.response ? {
            status: claimed.response.status,
            headers: normalizeHeaders(claimed.response.headers),
        } : null,
        connection,
        certificate_info: certInfo,
    };
}

/**
 * Add certificate_info to reconstructed transaction/message.
 * Uses EXTRACTED chain + claimed metadata (SNI, TLS version, etc).
 * @param {Object} reconstructed - Reconstructed transaction/message (mutated)
 * @param {Array} extractedCerts - Certificate chain extracted from handshake
 * @param {Object} claimedCertInfo - Claimed certificate_info from evidence
 */
export function addCertificateInfo(reconstructed, extractedCerts, claimedCertInfo) {
    if (!claimedCertInfo) return;

    const certInfo = {
        certificate_chain: extractedCerts,
    };

    if (claimedCertInfo.sni !== undefined) certInfo.sni = claimedCertInfo.sni;
    if (claimedCertInfo.tls_version !== undefined) certInfo.tls_version = claimedCertInfo.tls_version;
    if (claimedCertInfo.alpn !== undefined) certInfo.alpn = claimedCertInfo.alpn;
    if (claimedCertInfo.cipher_suite !== undefined) certInfo.cipher_suite = claimedCertInfo.cipher_suite;
    if (claimedCertInfo.handshake_proof !== undefined) certInfo.handshake_proof = claimedCertInfo.handshake_proof;

    reconstructed.certificate_info = certInfo;
}

/**
 * Stable JSON stringify with sorted keys for deterministic hashing.
 * @param {any} obj - Object to stringify
 * @returns {string} JSON string with sorted keys
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
 * Compute SHA-256 hash of a transaction object using stable stringify.
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
 * Concatenate payload arrays and return as a single Uint8Array
 */
export function concatenatePayloads(segments) {
    const payloads = segments.map(s => s.payload || s.data || s);
    return concatenate(payloads);
}

/**
 * Find differences between two objects recursively
 */
export function findDifferences(obj1, obj2, path = '') {
    const differences = [];

    const keys1 = Object.keys(obj1 || {});
    const keys2 = Object.keys(obj2 || {});
    const allKeys = new Set([...keys1, ...keys2]);

    for (const key of allKeys) {
        const newPath = path ? `${path}.${key}` : key;

        if (!(key in obj1)) {
            differences.push(`Missing in original: ${newPath}`);
        } else if (!(key in obj2)) {
            differences.push(`Missing in reconstructed: ${newPath}`);
        } else if (typeof obj1[key] === 'object' && obj1[key] !== null &&
                   typeof obj2[key] === 'object' && obj2[key] !== null) {
            if (Array.isArray(obj1[key]) && Array.isArray(obj2[key])) {
                if (obj1[key].length !== obj2[key].length) {
                    differences.push(`${newPath}: array length mismatch (${obj1[key].length} vs ${obj2[key].length})`);
                }
            } else {
                differences.push(...findDifferences(obj1[key], obj2[key], newPath));
            }
        } else if (obj1[key] !== obj2[key]) {
            const v1 = JSON.stringify(obj1[key]);
            const v2 = JSON.stringify(obj2[key]);
            differences.push(`${newPath}: ${v1} vs ${v2}`);
        }
    }

    return differences;
}
