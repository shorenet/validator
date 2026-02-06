/**
 * Byte conversion utilities
 */

import { base64ToBytes } from '../crypto/hash.js';

/**
 * Convert byte data to Uint8Array.
 * Handles both JSON array of numbers (from serde Vec<u8>) and base64 strings.
 * @param {Array<number>|string|Uint8Array} data - Byte data as array, base64 string, or Uint8Array
 * @returns {Uint8Array} Byte array
 */
export function toBytes(data) {
    if (!data) return new Uint8Array(0);
    if (data instanceof Uint8Array) return data;
    if (Array.isArray(data)) {
        // Rust serde serializes Vec<u8> as array of numbers
        return new Uint8Array(data);
    }
    if (typeof data === 'string') {
        // Base64 encoded string
        return base64ToBytes(data);
    }
    throw new Error(`Unknown byte data format: ${typeof data}`);
}

// Re-export base64ToBytes for convenience
export { base64ToBytes };
