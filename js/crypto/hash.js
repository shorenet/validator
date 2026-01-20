/**
 * SHA-256 hash utilities using Web Crypto API.
 * Verifies the hash chain in forensic evidence.
 */

/**
 * Compute SHA-256 hash of data.
 * @param {Uint8Array} data - Data to hash
 * @returns {Promise<Uint8Array>} 32-byte hash
 */
export async function sha256(data) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hashBuffer);
}

/**
 * Convert hex string to Uint8Array.
 * @param {string} hex - Hex string
 * @returns {Uint8Array}
 */
export function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

/**
 * Convert Uint8Array to hex string.
 * @param {Uint8Array} bytes - Bytes to convert
 * @returns {string} Lowercase hex string
 */
export function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Convert base64 string to Uint8Array.
 * @param {string} base64 - Base64 encoded string
 * @returns {Uint8Array}
 */
export function base64ToBytes(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

/**
 * Convert Uint8Array to base64 string.
 * @param {Uint8Array} bytes - Bytes to convert
 * @returns {string}
 */
export function bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/**
 * Verify hash chain integrity.
 * Each packet's hash should be: SHA256(previous_hash || packet_data)
 *
 * @param {Array<{data: string, hash: string, direction: string}>} packets - Packets with base64 data and hex hashes
 * @returns {Promise<{valid: boolean, details: Array}>}
 */
export async function verifyHashChain(packets) {
    const details = [];
    let valid = true;
    let previousHash = new Uint8Array(32); // Start with zeros

    for (let i = 0; i < packets.length; i++) {
        const packet = packets[i];
        const packetData = base64ToBytes(packet.data);
        const expectedHash = packet.hash;

        // Compute: SHA256(previous_hash || packet_data)
        const combined = new Uint8Array(previousHash.length + packetData.length);
        combined.set(previousHash);
        combined.set(packetData, previousHash.length);

        const computedHash = await sha256(combined);
        const computedHashHex = bytesToHex(computedHash);

        const matches = computedHashHex === expectedHash.toLowerCase();

        details.push({
            index: i,
            direction: packet.direction,
            size: packetData.length,
            expectedHash: expectedHash,
            computedHash: computedHashHex,
            valid: matches
        });

        if (!matches) {
            valid = false;
        }

        previousHash = computedHash;
    }

    return { valid, details, finalHash: bytesToHex(previousHash) };
}

/**
 * Verify a single content hash.
 * @param {Uint8Array|string} data - Data to verify (Uint8Array or base64 string)
 * @param {string} expectedHash - Expected hash in hex
 * @returns {Promise<{valid: boolean, computedHash: string}>}
 */
export async function verifyContentHash(data, expectedHash) {
    const bytes = typeof data === 'string' ? base64ToBytes(data) : data;
    const computedHash = await sha256(bytes);
    const computedHashHex = bytesToHex(computedHash);

    return {
        valid: computedHashHex === expectedHash.toLowerCase(),
        computedHash: computedHashHex
    };
}
