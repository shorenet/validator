/**
 * QPACK - HTTP/3 Header Compression (RFC 9204)
 * Pure JavaScript implementation for forensic validation.
 *
 * Ported from harbour's Rust implementation in crates/protocol-parser/src/http3/qpack.rs
 */

import { decodeHuffman } from '../../encoding/huffman.js';
import { decodeInteger } from '../../encoding/integer.js';
import { decodeVarint } from '../../encoding/varint.js';

/**
 * QPACK static table (RFC 9204 Appendix A).
 * Different from HPACK - 99 entries vs 61.
 */
const STATIC_TABLE = [
    [':authority', ''],
    [':path', '/'],
    ['age', '0'],
    ['content-disposition', ''],
    ['content-length', '0'],
    ['cookie', ''],
    ['date', ''],
    ['etag', ''],
    ['if-modified-since', ''],
    ['if-none-match', ''],
    ['last-modified', ''],
    ['link', ''],
    ['location', ''],
    ['referer', ''],
    ['set-cookie', ''],
    [':method', 'CONNECT'],
    [':method', 'DELETE'],
    [':method', 'GET'],
    [':method', 'HEAD'],
    [':method', 'OPTIONS'],
    [':method', 'POST'],
    [':method', 'PUT'],
    [':scheme', 'http'],
    [':scheme', 'https'],
    [':status', '103'],
    [':status', '200'],
    [':status', '304'],
    [':status', '404'],
    [':status', '503'],
    ['accept', '*/*'],
    ['accept', 'application/dns-message'],
    ['accept-encoding', 'gzip, deflate, br'],
    ['accept-ranges', 'bytes'],
    ['access-control-allow-headers', 'cache-control'],
    ['access-control-allow-headers', 'content-type'],
    ['access-control-allow-origin', '*'],
    ['cache-control', 'max-age=0'],
    ['cache-control', 'max-age=2592000'],
    ['cache-control', 'max-age=604800'],
    ['cache-control', 'no-cache'],
    ['cache-control', 'no-store'],
    ['cache-control', 'public, max-age=31536000'],
    ['content-encoding', 'br'],
    ['content-encoding', 'gzip'],
    ['content-type', 'application/dns-message'],
    ['content-type', 'application/javascript'],
    ['content-type', 'application/json'],
    ['content-type', 'application/x-www-form-urlencoded'],
    ['content-type', 'image/gif'],
    ['content-type', 'image/jpeg'],
    ['content-type', 'image/png'],
    ['content-type', 'text/css'],
    ['content-type', 'text/html; charset=utf-8'],
    ['content-type', 'text/plain'],
    ['content-type', 'text/plain;charset=utf-8'],
    ['range', 'bytes=0-'],
    ['strict-transport-security', 'max-age=31536000'],
    ['strict-transport-security', 'max-age=31536000; includesubdomains'],
    ['strict-transport-security', 'max-age=31536000; includesubdomains; preload'],
    ['vary', 'accept-encoding'],
    ['vary', 'origin'],
    ['x-content-type-options', 'nosniff'],
    ['x-xss-protection', '1; mode=block'],
    [':status', '100'],
    [':status', '204'],
    [':status', '206'],
    [':status', '302'],
    [':status', '400'],
    [':status', '403'],
    [':status', '421'],
    [':status', '425'],
    [':status', '500'],
    ['accept-language', ''],
    ['access-control-allow-credentials', 'FALSE'],
    ['access-control-allow-credentials', 'TRUE'],
    ['access-control-allow-headers', '*'],
    ['access-control-allow-methods', 'get'],
    ['access-control-allow-methods', 'get, post, options'],
    ['access-control-allow-methods', 'options'],
    ['access-control-expose-headers', 'content-length'],
    ['access-control-request-headers', 'content-type'],
    ['access-control-request-method', 'get'],
    ['access-control-request-method', 'post'],
    ['alt-svc', 'clear'],
    ['authorization', ''],
    ['content-security-policy', "script-src 'none'; object-src 'none'; base-uri 'none'"],
    ['early-data', '1'],
    ['expect-ct', ''],
    ['forwarded', ''],
    ['if-range', ''],
    ['origin', ''],
    ['purpose', 'prefetch'],
    ['server', ''],
    ['timing-allow-origin', '*'],
    ['upgrade-insecure-requests', '1'],
    ['user-agent', ''],
    ['x-forwarded-for', ''],
    ['x-frame-options', 'deny'],
    ['x-frame-options', 'sameorigin']
];

/**
 * Huffman encoding table (RFC 7541 Appendix B).
 * Same as HPACK - used for both HTTP/2 and HTTP/3.
 * Format: [code, code_length_in_bits]
 */
const HUFFMAN_ENCODE_TABLE = [
    [0x1ff8, 13], [0x7fffd8, 23], [0xfffffe2, 28], [0xfffffe3, 28],
    [0xfffffe4, 28], [0xfffffe5, 28], [0xfffffe6, 28], [0xfffffe7, 28],
    [0xfffffe8, 28], [0xffffea, 24], [0x3ffffffc, 30], [0xfffffe9, 28],
    [0xfffffea, 28], [0x3ffffffd, 30], [0xfffffeb, 28], [0xfffffec, 28],
    [0xfffffed, 28], [0xfffffee, 28], [0xfffffef, 28], [0xffffff0, 28],
    [0xffffff1, 28], [0xffffff2, 28], [0x3ffffffe, 30], [0xffffff3, 28],
    [0xffffff4, 28], [0xffffff5, 28], [0xffffff6, 28], [0xffffff7, 28],
    [0xffffff8, 28], [0xffffff9, 28], [0xffffffa, 28], [0xffffffb, 28],
    [0x14, 6], [0x3f8, 10], [0x3f9, 10], [0xffa, 12],
    [0x1ff9, 13], [0x15, 6], [0xf8, 8], [0x7fa, 11],
    [0x3fa, 10], [0x3fb, 10], [0xf9, 8], [0x7fb, 11],
    [0xfa, 8], [0x16, 6], [0x17, 6], [0x18, 6],
    [0x0, 5], [0x1, 5], [0x2, 5], [0x19, 6],
    [0x1a, 6], [0x1b, 6], [0x1c, 6], [0x1d, 6],
    [0x1e, 6], [0x1f, 6], [0x5c, 7], [0xfb, 8],
    [0x7ffc, 15], [0x20, 6], [0xffb, 12], [0x3fc, 10],
    [0x1ffa, 13], [0x21, 6], [0x5d, 7], [0x5e, 7],
    [0x5f, 7], [0x60, 7], [0x61, 7], [0x62, 7],
    [0x63, 7], [0x64, 7], [0x65, 7], [0x66, 7],
    [0x67, 7], [0x68, 7], [0x69, 7], [0x6a, 7],
    [0x6b, 7], [0x6c, 7], [0x6d, 7], [0x6e, 7],
    [0x6f, 7], [0x70, 7], [0x71, 7], [0x72, 7],
    [0xfc, 8], [0x73, 7], [0xfd, 8], [0x1ffb, 13],
    [0x7fff0, 19], [0x1ffc, 13], [0x3ffc, 14], [0x22, 6],
    [0x7ffd, 15], [0x3, 5], [0x23, 6], [0x4, 5],
    [0x24, 6], [0x5, 5], [0x25, 6], [0x26, 6],
    [0x27, 6], [0x6, 5], [0x74, 7], [0x75, 7],
    [0x28, 6], [0x29, 6], [0x2a, 6], [0x7, 5],
    [0x2b, 6], [0x76, 7], [0x2c, 6], [0x8, 5],
    [0x9, 5], [0x2d, 6], [0x77, 7], [0x78, 7],
    [0x79, 7], [0x7a, 7], [0x7b, 7], [0x7ffe, 15],
    [0x7fc, 11], [0x3ffd, 14], [0x1ffd, 13], [0xffffffc, 28],
    [0xfffe6, 20], [0x3fffd2, 22], [0xfffe7, 20], [0xfffe8, 20],
    [0x3fffd3, 22], [0x3fffd4, 22], [0x3fffd5, 22], [0x7fffd9, 23],
    [0x3fffd6, 22], [0x7fffda, 23], [0x7fffdb, 23], [0x7fffdc, 23],
    [0x7fffdd, 23], [0x7fffde, 23], [0xffffeb, 24], [0x7fffdf, 23],
    [0xffffec, 24], [0xffffed, 24], [0x3fffd7, 22], [0x7fffe0, 23],
    [0xffffee, 24], [0x7fffe1, 23], [0x7fffe2, 23], [0x7fffe3, 23],
    [0x7fffe4, 23], [0x1fffdc, 21], [0x3fffd8, 22], [0x7fffe5, 23],
    [0x3fffd9, 22], [0x7fffe6, 23], [0x7fffe7, 23], [0xffffef, 24],
    [0x3fffda, 22], [0x1fffdd, 21], [0xfffe9, 20], [0x3fffdb, 22],
    [0x3fffdc, 22], [0x7fffe8, 23], [0x7fffe9, 23], [0x1fffde, 21],
    [0x7fffea, 23], [0x3fffdd, 22], [0x3fffde, 22], [0xfffff0, 24],
    [0x1fffdf, 21], [0x3fffdf, 22], [0x7fffeb, 23], [0x7fffec, 23],
    [0x1fffe0, 21], [0x1fffe1, 21], [0x3fffe0, 22], [0x1fffe2, 21],
    [0x7fffed, 23], [0x3fffe1, 22], [0x7fffee, 23], [0x7fffef, 23],
    [0xfffea, 20], [0x3fffe2, 22], [0x3fffe3, 22], [0x3fffe4, 22],
    [0x7ffff0, 23], [0x3fffe5, 22], [0x3fffe6, 22], [0x7ffff1, 23],
    [0x3ffffe0, 26], [0x3ffffe1, 26], [0xfffeb, 20], [0x7fff1, 19],
    [0x3fffe7, 22], [0x7ffff2, 23], [0x3fffe8, 22], [0x1ffffec, 25],
    [0x3ffffe2, 26], [0x3ffffe3, 26], [0x3ffffe4, 26], [0x7ffffde, 27],
    [0x7ffffdf, 27], [0x3ffffe5, 26], [0xfffff1, 24], [0x1ffffed, 25],
    [0x7fff2, 19], [0x1fffe3, 21], [0x3ffffe6, 26], [0x7ffffe0, 27],
    [0x7ffffe1, 27], [0x3ffffe7, 26], [0x7ffffe2, 27], [0xfffff2, 24],
    [0x1fffe4, 21], [0x1fffe5, 21], [0x3ffffe8, 26], [0x3ffffe9, 26],
    [0xffffffd, 28], [0x7ffffe3, 27], [0x7ffffe4, 27], [0x7ffffe5, 27],
    [0xfffec, 20], [0xfffff3, 24], [0xfffed, 20], [0x1fffe6, 21],
    [0x3fffe9, 22], [0x1fffe7, 21], [0x1fffe8, 21], [0x7ffff3, 23],
    [0x3fffea, 22], [0x3fffeb, 22], [0x1ffffee, 25], [0x1ffffef, 25],
    [0xfffff4, 24], [0xfffff5, 24], [0x3ffffea, 26], [0x7ffff4, 23],
    [0x3ffffeb, 26], [0x7ffffe6, 27], [0x3ffffec, 26], [0x3ffffed, 26],
    [0x7ffffe7, 27], [0x7ffffe8, 27], [0x7ffffe9, 27], [0x7ffffea, 27],
    [0x7ffffeb, 27], [0xffffffe, 28], [0x7ffffec, 27], [0x7ffffed, 27],
    [0x7ffffee, 27], [0x7ffffef, 27], [0x7fffff0, 27], [0x3ffffee, 26],
    [0x3fffffff, 30] // EOS
];

// decodeHuffman now imported from shared encoding module

// decodeInteger now imported from shared encoding module

/**
 * Decode a QPACK string (with or without Huffman encoding).
 * @param {Uint8Array} data - Data to decode from
 * @param {number} offset - Starting offset
 * @returns {{value: string, bytesRead: number}}
 */
function decodeString(data, offset) {
    if (offset >= data.length) {
        throw new Error('Empty string data');
    }

    const huffman = (data[offset] & 0x80) !== 0;
    const { value: length, bytesRead: lenBytes } = decodeInteger(data, offset, 7);

    if (offset + lenBytes + length > data.length) {
        throw new Error('String truncated');
    }

    const strData = data.slice(offset + lenBytes, offset + lenBytes + length);
    let value;

    if (huffman) {
        value = decodeHuffman(strData);
    } else {
        value = new TextDecoder().decode(strData);
    }

    return { value, bytesRead: lenBytes + length };
}

/**
 * QPACK decoder with dynamic table support.
 */
export class QpackDecoder {
    constructor(maxCapacity = 4096) {
        this.dynamicTable = [];
        this.maxCapacity = maxCapacity;
        this.currentSize = 0;
        this.knownReceivedCount = 0;
        this.encoderStreamCorrupted = false;
    }

    /**
     * Get entry from static table.
     * @param {number} index - 0-based index
     * @returns {[string, string]} [name, value]
     */
    getStatic(index) {
        if (index >= STATIC_TABLE.length) {
            throw new Error(`Invalid static table index: ${index}`);
        }
        return [...STATIC_TABLE[index]];
    }

    /**
     * Try to get entry from static table, returning null if invalid.
     * @param {number} index - 0-based index
     * @returns {[string, string]|null}
     */
    tryGetStatic(index) {
        if (index >= STATIC_TABLE.length) {
            return null;
        }
        return [...STATIC_TABLE[index]];
    }

    /**
     * Get entry from dynamic table using absolute index.
     * @param {number} absoluteIndex - Absolute index (0 = first entry ever inserted)
     * @returns {[string, string]}
     */
    getDynamicAbsolute(absoluteIndex) {
        const firstValid = Math.max(0, this.knownReceivedCount - this.dynamicTable.length);

        if (absoluteIndex < firstValid) {
            throw new Error(`Dynamic table entry evicted: ${absoluteIndex} < ${firstValid}`);
        }

        if (absoluteIndex >= this.knownReceivedCount) {
            throw new Error(`Dynamic table entry not yet inserted: ${absoluteIndex} >= ${this.knownReceivedCount}`);
        }

        const vecPosition = this.knownReceivedCount - 1 - absoluteIndex;
        if (vecPosition >= this.dynamicTable.length) {
            throw new Error(`Dynamic table index out of bounds: ${vecPosition} >= ${this.dynamicTable.length}`);
        }

        return [...this.dynamicTable[vecPosition]];
    }

    /**
     * Try to get entry from dynamic table, returning null if not available.
     * @param {number} absoluteIndex - Absolute index
     * @returns {[string, string]|null}
     */
    tryGetDynamicAbsolute(absoluteIndex) {
        const firstValid = Math.max(0, this.knownReceivedCount - this.dynamicTable.length);

        if (absoluteIndex < firstValid || absoluteIndex >= this.knownReceivedCount) {
            return null;
        }

        const vecPosition = this.knownReceivedCount - 1 - absoluteIndex;
        if (vecPosition >= this.dynamicTable.length) {
            return null;
        }

        return [...this.dynamicTable[vecPosition]];
    }

    /**
     * Get entry from dynamic table using relative index (for encoder stream).
     * @param {number} relativeIndex - Relative index (0 = most recent entry)
     * @returns {[string, string]}
     */
    getDynamic(relativeIndex) {
        if (relativeIndex >= this.dynamicTable.length) {
            // Return placeholder for lenient decoding
            return [`x-dyn-ref-${relativeIndex}`, ''];
        }
        return [...this.dynamicTable[relativeIndex]];
    }

    /**
     * Add entry to dynamic table.
     * @param {string} name - Header name
     * @param {string} value - Header value
     */
    addEntry(name, value) {
        const entrySize = name.length + value.length + 32;

        // Always increment insert count per RFC 9204
        this.knownReceivedCount++;

        // Evict entries if needed
        while (this.currentSize + entrySize > this.maxCapacity && this.dynamicTable.length > 0) {
            const [oldName, oldValue] = this.dynamicTable.pop();
            this.currentSize -= oldName.length + oldValue.length + 32;
        }

        if (entrySize <= this.maxCapacity) {
            this.dynamicTable.unshift([name, value]);
            this.currentSize += entrySize;
        }
    }

    /**
     * Set maximum table capacity.
     * @param {number} capacity - New capacity
     */
    setMaxCapacity(capacity) {
        this.maxCapacity = capacity;
        while (this.currentSize > this.maxCapacity && this.dynamicTable.length > 0) {
            const [name, value] = this.dynamicTable.pop();
            this.currentSize -= name.length + value.length + 32;
        }
    }

    /**
     * Decode the Required Insert Count from encoded form (RFC 9204 Section 4.5.1.1).
     * @param {number} encoded - Encoded RIC
     * @returns {number} Decoded RIC
     */
    decodeRequiredInsertCount(encoded) {
        if (encoded === 0) {
            return 0;
        }

        const maxEntries = Math.floor(this.maxCapacity / 32);
        if (maxEntries === 0) {
            throw new Error('Non-zero RIC with zero dynamic table capacity');
        }

        const fullRange = 2 * maxEntries;
        if (encoded > fullRange) {
            throw new Error(`EncodedInsertCount ${encoded} exceeds 2*MaxEntries ${fullRange}`);
        }

        const totalInserts = this.knownReceivedCount;
        const maxValue = totalInserts + maxEntries;
        const maxWrapped = Math.floor(maxValue / fullRange) * fullRange;
        let reqInsertCount = maxWrapped + encoded - 1;

        if (reqInsertCount > maxValue) {
            if (reqInsertCount <= fullRange) {
                throw new Error('Invalid Required Insert Count encoding');
            }
            reqInsertCount -= fullRange;
        }

        if (reqInsertCount === 0) {
            throw new Error('Decoded Required Insert Count is 0 from non-zero encoded value');
        }

        return reqInsertCount;
    }

    /**
     * Process encoder stream data (RFC 9204 Section 4.3).
     * @param {Uint8Array} data - Encoder stream data
     * @returns {number} Bytes consumed
     */
    processEncoderStream(data) {
        let offset = 0;
        let lastCompleteOffset = 0;

        while (offset < data.length) {
            const firstByte = data[offset];

            try {
                if ((firstByte & 0xc0) === 0xc0) {
                    // Insert With Name Reference - Static Table (0b11xxxxxx)
                    const { value: nameIdx, bytesRead } = decodeInteger(data, offset, 6);
                    offset += bytesRead;

                    const [name] = this.getStatic(nameIdx);
                    const { value, bytesRead: valueBytes } = decodeString(data, offset);
                    offset += valueBytes;

                    this.addEntry(name, value);
                } else if ((firstByte & 0xc0) === 0x80) {
                    // Insert With Name Reference - Dynamic Table (0b10xxxxxx)
                    const { value: nameIdx, bytesRead } = decodeInteger(data, offset, 6);
                    offset += bytesRead;

                    const [name] = this.getDynamic(nameIdx);
                    const { value, bytesRead: valueBytes } = decodeString(data, offset);
                    offset += valueBytes;

                    this.addEntry(name, value);
                } else if ((firstByte & 0xc0) === 0x40) {
                    // Insert With Literal Name (0b01xxxxxx)
                    const huffmanName = (firstByte & 0x20) !== 0;
                    const { value: nameLen, bytesRead } = decodeInteger(data, offset, 5);
                    offset += bytesRead;

                    if (offset + nameLen > data.length) {
                        return lastCompleteOffset;
                    }

                    const nameData = data.slice(offset, offset + nameLen);
                    offset += nameLen;

                    const name = huffmanName ? decodeHuffman(nameData) : new TextDecoder().decode(nameData);

                    const { value, bytesRead: valueBytes } = decodeString(data, offset);
                    offset += valueBytes;

                    this.addEntry(name, value);
                } else if ((firstByte & 0xe0) === 0x20) {
                    // Set Dynamic Table Capacity (0b001xxxxx)
                    const { value: capacity, bytesRead } = decodeInteger(data, offset, 5);
                    offset += bytesRead;
                    this.setMaxCapacity(capacity);
                } else {
                    // Duplicate (0b000xxxxx)
                    const { value: index, bytesRead } = decodeInteger(data, offset, 5);
                    offset += bytesRead;

                    const [name, value] = this.getDynamic(index);
                    this.addEntry(name, value);
                }

                lastCompleteOffset = offset;
            } catch (e) {
                // Return bytes consumed up to last complete instruction
                return lastCompleteOffset;
            }
        }

        return offset;
    }

    /**
     * Decode a QPACK-encoded header block.
     * @param {Uint8Array} data - Header block data
     * @param {boolean} lenient - If true, skip invalid entries instead of failing
     * @param {number|null} storedRic - Pre-decoded RIC for deferred decoding
     * @returns {Array<[string, string]>} Decoded headers
     */
    decode(data, lenient = true, storedRic = null) {
        const headers = [];
        let offset = 0;

        if (data.length === 0) {
            return headers;
        }

        // Decode Required Insert Count
        const { value: encodedRic, bytesRead: ricLen } = decodeInteger(data, 0, 8);
        offset += ricLen;

        if (offset >= data.length) {
            return headers;
        }

        // Decode RIC
        const requiredInsertCount = storedRic !== null
            ? storedRic
            : this.decodeRequiredInsertCount(encodedRic);

        // Reject if encoder stream is corrupted and RIC > 0
        if (this.encoderStreamCorrupted && requiredInsertCount > 0) {
            throw new Error('Cannot decode headers with dynamic table references: encoder stream corrupted');
        }

        // Decode Base
        const { value: deltaBase, bytesRead: dbLen } = decodeInteger(data, offset, 7);
        const sign = (data[offset] & 0x80) !== 0;
        offset += dbLen;

        // Compute Base per RFC 9204 Section 4.5.1.2
        const base = sign
            ? Math.max(0, requiredInsertCount - deltaBase - 1)
            : requiredInsertCount + deltaBase;

        // Decode header field lines
        // Safety limit: max 1000 headers to prevent infinite loops from corrupted data
        const maxHeaders = 1000;
        let iterations = 0;
        while (offset < data.length && iterations < maxHeaders) {
            iterations++;
            const prevOffset = offset;
            const firstByte = data[offset];

            try {
                if ((firstByte & 0x80) !== 0) {
                    // Indexed Field Line (Section 4.5.2)
                    const staticRef = (firstByte & 0x40) !== 0;
                    const { value: relativeIndex, bytesRead } = decodeInteger(data, offset, 6);
                    offset += bytesRead;

                    if (staticRef) {
                        const entry = lenient ? this.tryGetStatic(relativeIndex) : this.getStatic(relativeIndex);
                        if (entry) {
                            headers.push(entry);
                        }
                    } else {
                        // Dynamic table reference
                        if (base === 0 || relativeIndex >= base) {
                            if (!lenient) {
                                throw new Error(`Invalid dynamic index: relativeIndex ${relativeIndex} >= base ${base}`);
                            }
                        } else {
                            const absoluteIndex = base - relativeIndex - 1;
                            const entry = lenient
                                ? this.tryGetDynamicAbsolute(absoluteIndex)
                                : this.getDynamicAbsolute(absoluteIndex);
                            if (entry) {
                                headers.push(entry);
                            }
                        }
                    }
                } else if ((firstByte & 0x40) !== 0) {
                    // Literal Field Line with Name Reference (Section 4.5.4)
                    const staticRef = (firstByte & 0x10) !== 0;
                    const { value: relativeIndex, bytesRead } = decodeInteger(data, offset, 4);
                    offset += bytesRead;

                    let name = null;
                    if (staticRef) {
                        const entry = lenient ? this.tryGetStatic(relativeIndex) : this.getStatic(relativeIndex);
                        if (entry) {
                            name = entry[0];
                        }
                    } else {
                        if (base > 0 && relativeIndex < base) {
                            const absoluteIndex = base - relativeIndex - 1;
                            const entry = lenient
                                ? this.tryGetDynamicAbsolute(absoluteIndex)
                                : this.getDynamicAbsolute(absoluteIndex);
                            if (entry) {
                                name = entry[0];
                            }
                        }
                    }

                    const { value, bytesRead: valueBytes } = decodeString(data, offset);
                    offset += valueBytes;

                    if (name !== null) {
                        headers.push([name, value]);
                    }
                } else if ((firstByte & 0x20) !== 0) {
                    // Literal Field Line with Literal Name (Section 4.5.6)
                    // First byte format: 001NHLLL where H is Huffman flag for name, 3-bit length prefix
                    const nameHuffman = (firstByte & 0x08) !== 0;
                    const { value: nameLen, bytesRead: nameLenBytes } = decodeInteger(data, offset, 3);
                    offset += nameLenBytes;

                    if (offset + nameLen > data.length) {
                        throw new Error('Name string truncated');
                    }

                    const nameData = data.slice(offset, offset + nameLen);
                    offset += nameLen;
                    const name = nameHuffman ? decodeHuffman(nameData) : new TextDecoder().decode(nameData);

                    // Value uses standard string encoding (H at bit 7, 7-bit prefix)
                    const { value, bytesRead: valueBytes } = decodeString(data, offset);
                    offset += valueBytes;

                    headers.push([name, value]);
                } else if ((firstByte & 0x10) !== 0) {
                    // Indexed Field Line with Post-Base Index (Section 4.5.3)
                    const { value: postBaseIndex, bytesRead } = decodeInteger(data, offset, 4);
                    offset += bytesRead;

                    const absoluteIndex = base + postBaseIndex;
                    const entry = lenient
                        ? this.tryGetDynamicAbsolute(absoluteIndex)
                        : this.getDynamicAbsolute(absoluteIndex);
                    if (entry) {
                        headers.push(entry);
                    }
                } else {
                    // Literal Field Line with Post-Base Name Reference (Section 4.5.5)
                    const { value: postBaseIndex, bytesRead } = decodeInteger(data, offset, 3);
                    offset += bytesRead;

                    const absoluteIndex = base + postBaseIndex;
                    let name = null;
                    const entry = lenient
                        ? this.tryGetDynamicAbsolute(absoluteIndex)
                        : this.getDynamicAbsolute(absoluteIndex);
                    if (entry) {
                        name = entry[0];
                    }

                    const { value, bytesRead: valueBytes } = decodeString(data, offset);
                    offset += valueBytes;

                    if (name !== null) {
                        headers.push([name, value]);
                    }
                }

                // Safety: ensure offset advanced to prevent infinite loops
                if (offset === prevOffset) {
                    if (lenient) {
                        return headers;
                    }
                    throw new Error('QPACK decode stuck: offset not advancing');
                }
            } catch (e) {
                if (lenient) {
                    return headers;
                }
                throw e;
            }
        }

        return headers;
    }

    /**
     * Extract Required Insert Count from header block without decoding.
     * @param {Uint8Array} data - Header block data
     * @returns {number} Required Insert Count
     */
    extractRequiredInsertCount(data) {
        if (data.length === 0) {
            return 0;
        }
        const { value: encodedRic } = decodeInteger(data, 0, 8);
        return this.decodeRequiredInsertCount(encodedRic);
    }

    /**
     * Check if a header block can be decoded with current state.
     * @param {Uint8Array} data - Header block data
     * @returns {boolean}
     */
    canDecode(data) {
        try {
            const ric = this.extractRequiredInsertCount(data);
            return ric === 0 || this.knownReceivedCount >= ric;
        } catch {
            return false;
        }
    }

    /**
     * Mark encoder stream as corrupted.
     */
    markCorrupted() {
        this.encoderStreamCorrupted = true;
    }

    /**
     * Get current state for debugging.
     */
    getState() {
        return {
            dynamicTableSize: this.dynamicTable.length,
            currentSize: this.currentSize,
            maxCapacity: this.maxCapacity,
            knownReceivedCount: this.knownReceivedCount,
            encoderStreamCorrupted: this.encoderStreamCorrupted
        };
    }
}

export { STATIC_TABLE, decodeHuffman, decodeInteger, decodeString };
