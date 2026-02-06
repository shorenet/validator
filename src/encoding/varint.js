/**
 * QUIC variable-length integer encoding (RFC 9000 Section 16)
 * Used by QUIC, HTTP/3, and QPACK
 *
 * Format:
 * - 2 most significant bits indicate length (00=1 byte, 01=2 bytes, 10=4 bytes, 11=8 bytes)
 * - Remaining bits contain the value
 */

/**
 * Decode a QUIC variable-length integer.
 *
 * @param {Uint8Array} data - Data to decode from
 * @param {number} offset - Starting offset (default: 0)
 * @returns {{value: number, bytesRead: number}} Decoded value and bytes consumed
 * @throws {Error} If data is truncated or invalid
 */
export function decodeVarint(data, offset = 0) {
    if (offset >= data.length) {
        throw new Error('Empty data for varint');
    }

    const firstByte = data[offset];
    const prefix = firstByte >> 6;

    let value;
    let bytesRead;

    switch (prefix) {
        case 0: // 1-byte (6-bit value)
            value = firstByte & 0x3f;
            bytesRead = 1;
            break;

        case 1: // 2-byte (14-bit value)
            if (offset + 2 > data.length) {
                throw new Error('Truncated 2-byte varint');
            }
            value = ((firstByte & 0x3f) << 8) | data[offset + 1];
            bytesRead = 2;
            break;

        case 2: // 4-byte (30-bit value)
            if (offset + 4 > data.length) {
                throw new Error('Truncated 4-byte varint');
            }
            value = ((firstByte & 0x3f) << 24) |
                    (data[offset + 1] << 16) |
                    (data[offset + 2] << 8) |
                    data[offset + 3];
            bytesRead = 4;
            break;

        case 3: // 8-byte (62-bit value)
            if (offset + 8 > data.length) {
                throw new Error('Truncated 8-byte varint');
            }
            // JavaScript doesn't handle 64-bit integers well, so we use BigInt
            const high = BigInt((firstByte & 0x3f)) << 56n |
                        BigInt(data[offset + 1]) << 48n |
                        BigInt(data[offset + 2]) << 40n |
                        BigInt(data[offset + 3]) << 32n;
            const low = BigInt(data[offset + 4]) << 24n |
                       BigInt(data[offset + 5]) << 16n |
                       BigInt(data[offset + 6]) << 8n |
                       BigInt(data[offset + 7]);
            value = Number(high | low);
            bytesRead = 8;
            break;

        default:
            throw new Error('Invalid varint prefix');
    }

    return { value, bytesRead };
}

/**
 * Encode a number as a QUIC variable-length integer.
 * Automatically selects the smallest encoding that can hold the value.
 *
 * @param {number} value - Value to encode (0 to 2^62 - 1)
 * @returns {Uint8Array} Encoded varint
 * @throws {Error} If value is negative or too large
 */
export function encodeVarint(value) {
    if (value < 0) {
        throw new Error('Varint value cannot be negative');
    }

    if (value < 0x40) { // 6 bits (0-63)
        return new Uint8Array([value]);
    } else if (value < 0x4000) { // 14 bits (0-16383)
        return new Uint8Array([
            0x40 | (value >> 8),
            value & 0xff
        ]);
    } else if (value < 0x40000000) { // 30 bits (0-1073741823)
        return new Uint8Array([
            0x80 | (value >> 24),
            (value >> 16) & 0xff,
            (value >> 8) & 0xff,
            value & 0xff
        ]);
    } else if (value < 0x4000000000000000) { // 62 bits
        const high = Math.floor(value / 0x100000000);
        const low = value >>> 0;
        return new Uint8Array([
            0xc0 | (high >> 24),
            (high >> 16) & 0xff,
            (high >> 8) & 0xff,
            high & 0xff,
            (low >> 24) & 0xff,
            (low >> 16) & 0xff,
            (low >> 8) & 0xff,
            low & 0xff
        ]);
    } else {
        throw new Error('Varint value too large (max 2^62 - 1)');
    }
}

/**
 * Get the length of a varint from its first byte.
 * Useful for determining how many bytes to read without decoding the full value.
 *
 * @param {number} firstByte - First byte of the varint
 * @returns {number} Length in bytes (1, 2, 4, or 8)
 */
export function varintLength(firstByte) {
    const prefix = firstByte >> 6;
    return [1, 2, 4, 8][prefix];
}
