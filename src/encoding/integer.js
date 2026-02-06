/**
 * HPACK/QPACK integer encoding (RFC 7541 Section 5.1, RFC 9204)
 * Prefix-encoded integers used in header compression.
 *
 * Integers are encoded with a variable-length format where:
 * - If the value fits in the prefix bits, it's encoded directly
 * - Otherwise, the prefix is filled with 1s and continuation bytes follow
 *
 * Example with 5-bit prefix:
 * - Value 10: 0b001010 (fits in 5 bits, encoded in 1 byte)
 * - Value 1337: 0b11111 + continuation bytes (doesn't fit, needs multiple bytes)
 */

/**
 * Decode an HPACK/QPACK integer with the given prefix bits.
 *
 * @param {Uint8Array} data - Data to decode from
 * @param {number} offset - Starting offset
 * @param {number} prefixBits - Number of prefix bits (1-8)
 * @returns {{value: number, bytesRead: number}} Decoded value and bytes consumed
 * @throws {Error} If data is invalid or causes integer overflow
 */
export function decodeInteger(data, offset, prefixBits) {
    if (offset >= data.length) {
        throw new Error('Empty data for integer decode');
    }

    if (prefixBits < 1 || prefixBits > 8) {
        throw new Error(`Invalid prefix bits: ${prefixBits} (must be 1-8)`);
    }

    const prefixMask = (1 << prefixBits) - 1;
    let value = data[offset] & prefixMask;
    let bytesRead = 1;

    // If value is less than the max for this prefix, we're done
    if (value < prefixMask) {
        return { value, bytesRead };
    }

    // Multi-byte integer: read continuation bytes
    // Each byte contributes 7 bits, with the high bit indicating more bytes follow
    let shift = 0;
    while (offset + bytesRead < data.length) {
        const byte = data[offset + bytesRead];
        bytesRead++;

        value += (byte & 0x7f) << shift;
        shift += 7;

        // If high bit is 0, this is the last byte
        if ((byte & 0x80) === 0) {
            break;
        }

        // Prevent overflow from malicious input
        if (shift > 56) {
            throw new Error('Integer overflow in decodeInteger');
        }
    }

    return { value, bytesRead };
}

/**
 * Encode an integer with the given prefix bits.
 * This is the inverse of decodeInteger.
 *
 * @param {number} value - Value to encode (must be non-negative)
 * @param {number} prefixBits - Number of prefix bits (1-8)
 * @param {number} prefixData - Existing data in the non-prefix bits of first byte (default: 0)
 * @returns {Uint8Array} Encoded integer
 * @throws {Error} If value is negative or prefixBits invalid
 */
export function encodeInteger(value, prefixBits, prefixData = 0) {
    if (value < 0) {
        throw new Error('Cannot encode negative integer');
    }

    if (prefixBits < 1 || prefixBits > 8) {
        throw new Error(`Invalid prefix bits: ${prefixBits} (must be 1-8)`);
    }

    const prefixMask = (1 << prefixBits) - 1;
    const bytes = [];

    // If value fits in prefix bits, encode in single byte
    if (value < prefixMask) {
        bytes.push(prefixData | value);
        return new Uint8Array(bytes);
    }

    // Value doesn't fit - fill prefix with 1s and use continuation bytes
    bytes.push(prefixData | prefixMask);
    value -= prefixMask;

    // Encode remaining value in 7-bit chunks
    while (value >= 128) {
        bytes.push((value & 0x7f) | 0x80);
        value >>= 7;
    }
    bytes.push(value);

    return new Uint8Array(bytes);
}
