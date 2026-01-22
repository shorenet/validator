/**
 * HPACK - HTTP/2 Header Compression (RFC 7541)
 * Pure JavaScript implementation for forensic validation.
 */

/**
 * HPACK static table (RFC 7541 Appendix A).
 * Index 1-61 are predefined header fields.
 */
const STATIC_TABLE = [
    null, // Index 0 is unused
    [':authority', ''],
    [':method', 'GET'],
    [':method', 'POST'],
    [':path', '/'],
    [':path', '/index.html'],
    [':scheme', 'http'],
    [':scheme', 'https'],
    [':status', '200'],
    [':status', '204'],
    [':status', '206'],
    [':status', '304'],
    [':status', '400'],
    [':status', '404'],
    [':status', '500'],
    ['accept-charset', ''],
    ['accept-encoding', 'gzip, deflate'],
    ['accept-language', ''],
    ['accept-ranges', ''],
    ['accept', ''],
    ['access-control-allow-origin', ''],
    ['age', ''],
    ['allow', ''],
    ['authorization', ''],
    ['cache-control', ''],
    ['content-disposition', ''],
    ['content-encoding', ''],
    ['content-language', ''],
    ['content-length', ''],
    ['content-location', ''],
    ['content-range', ''],
    ['content-type', ''],
    ['cookie', ''],
    ['date', ''],
    ['etag', ''],
    ['expect', ''],
    ['expires', ''],
    ['from', ''],
    ['host', ''],
    ['if-match', ''],
    ['if-modified-since', ''],
    ['if-none-match', ''],
    ['if-range', ''],
    ['if-unmodified-since', ''],
    ['last-modified', ''],
    ['link', ''],
    ['location', ''],
    ['max-forwards', ''],
    ['proxy-authenticate', ''],
    ['proxy-authorization', ''],
    ['range', ''],
    ['referer', ''],
    ['refresh', ''],
    ['retry-after', ''],
    ['server', ''],
    ['set-cookie', ''],
    ['strict-transport-security', ''],
    ['transfer-encoding', ''],
    ['user-agent', ''],
    ['vary', ''],
    ['via', ''],
    ['www-authenticate', '']
];

/**
 * Huffman decoding table (RFC 7541 Appendix B).
 * Maps Huffman codes to their decoded characters.
 */
const HUFFMAN_TABLE = buildHuffmanTable();

function buildHuffmanTable() {
    // Huffman codes from RFC 7541 Appendix B
    // Format: [symbol, code_bits, code_length]
    const codes = [
        [0, 0x1ff8, 13], [1, 0x7fffd8, 23], [2, 0xfffffe2, 28], [3, 0xfffffe3, 28],
        [4, 0xfffffe4, 28], [5, 0xfffffe5, 28], [6, 0xfffffe6, 28], [7, 0xfffffe7, 28],
        [8, 0xfffffe8, 28], [9, 0xffffea, 24], [10, 0x3ffffffc, 30], [11, 0xfffffe9, 28],
        [12, 0xfffffea, 28], [13, 0x3ffffffd, 30], [14, 0xfffffeb, 28], [15, 0xfffffec, 28],
        [16, 0xfffffed, 28], [17, 0xfffffee, 28], [18, 0xfffffef, 28], [19, 0xffffff0, 28],
        [20, 0xffffff1, 28], [21, 0xffffff2, 28], [22, 0x3ffffffe, 30], [23, 0xffffff3, 28],
        [24, 0xffffff4, 28], [25, 0xffffff5, 28], [26, 0xffffff6, 28], [27, 0xffffff7, 28],
        [28, 0xffffff8, 28], [29, 0xffffff9, 28], [30, 0xffffffa, 28], [31, 0xffffffb, 28],
        [32, 0x14, 6], [33, 0x3f8, 10], [34, 0x3f9, 10], [35, 0xffa, 12],
        [36, 0x1ff9, 13], [37, 0x15, 6], [38, 0xf8, 8], [39, 0x7fa, 11],
        [40, 0x3fa, 10], [41, 0x3fb, 10], [42, 0xf9, 8], [43, 0x7fb, 11],
        [44, 0xfa, 8], [45, 0x16, 6], [46, 0x17, 6], [47, 0x18, 6],
        [48, 0x0, 5], [49, 0x1, 5], [50, 0x2, 5], [51, 0x19, 6],
        [52, 0x1a, 6], [53, 0x1b, 6], [54, 0x1c, 6], [55, 0x1d, 6],
        [56, 0x1e, 6], [57, 0x1f, 6], [58, 0x5c, 7], [59, 0xfb, 8],
        [60, 0x7ffc, 15], [61, 0x20, 6], [62, 0xffb, 12], [63, 0x3fc, 10],
        [64, 0x1ffa, 13], [65, 0x21, 6], [66, 0x5d, 7], [67, 0x5e, 7],
        [68, 0x5f, 7], [69, 0x60, 7], [70, 0x61, 7], [71, 0x62, 7],
        [72, 0x63, 7], [73, 0x64, 7], [74, 0x65, 7], [75, 0x66, 7],
        [76, 0x67, 7], [77, 0x68, 7], [78, 0x69, 7], [79, 0x6a, 7],
        [80, 0x6b, 7], [81, 0x6c, 7], [82, 0x6d, 7], [83, 0x6e, 7],
        [84, 0x6f, 7], [85, 0x70, 7], [86, 0x71, 7], [87, 0x72, 7],
        [88, 0xfc, 8], [89, 0x73, 7], [90, 0xfd, 8], [91, 0x1ffb, 13],
        [92, 0x7fff0, 19], [93, 0x1ffc, 13], [94, 0x3ffc, 14], [95, 0x22, 6],
        [96, 0x7ffd, 15], [97, 0x3, 5], [98, 0x23, 6], [99, 0x4, 5],
        [100, 0x24, 6], [101, 0x5, 5], [102, 0x25, 6], [103, 0x26, 6],
        [104, 0x27, 6], [105, 0x6, 5], [106, 0x74, 7], [107, 0x75, 7],
        [108, 0x28, 6], [109, 0x29, 6], [110, 0x2a, 6], [111, 0x7, 5],
        [112, 0x2b, 6], [113, 0x76, 7], [114, 0x2c, 6], [115, 0x8, 5],
        [116, 0x9, 5], [117, 0x2d, 6], [118, 0x77, 7], [119, 0x78, 7],
        [120, 0x79, 7], [121, 0x7a, 7], [122, 0x7b, 7], [123, 0x7ffe, 15],
        [124, 0x7fc, 11], [125, 0x3ffd, 14], [126, 0x1ffd, 13], [127, 0xffffffc, 28],
        [128, 0xfffe6, 20], [129, 0x3fffd2, 22], [130, 0xfffe7, 20], [131, 0xfffe8, 20],
        [132, 0x3fffd3, 22], [133, 0x3fffd4, 22], [134, 0x3fffd5, 22], [135, 0x7fffd9, 23],
        [136, 0x3fffd6, 22], [137, 0x7fffda, 23], [138, 0x7fffdb, 23], [139, 0x7fffdc, 23],
        [140, 0x7fffdd, 23], [141, 0x7fffde, 23], [142, 0xffffeb, 24], [143, 0x7fffdf, 23],
        [144, 0xffffec, 24], [145, 0xffffed, 24], [146, 0x3fffd7, 22], [147, 0x7fffe0, 23],
        [148, 0xffffee, 24], [149, 0x7fffe1, 23], [150, 0x7fffe2, 23], [151, 0x7fffe3, 23],
        [152, 0x7fffe4, 23], [153, 0x1fffdc, 21], [154, 0x3fffd8, 22], [155, 0x7fffe5, 23],
        [156, 0x3fffd9, 22], [157, 0x7fffe6, 23], [158, 0x7fffe7, 23], [159, 0xffffef, 24],
        [160, 0x3fffda, 22], [161, 0x1fffdd, 21], [162, 0xfffe9, 20], [163, 0x3fffdb, 22],
        [164, 0x3fffdc, 22], [165, 0x7fffe8, 23], [166, 0x7fffe9, 23], [167, 0x1fffde, 21],
        [168, 0x7fffea, 23], [169, 0x3fffdd, 22], [170, 0x3fffde, 22], [171, 0xfffff0, 24],
        [172, 0x1fffdf, 21], [173, 0x3fffdf, 22], [174, 0x7fffeb, 23], [175, 0x7fffec, 23],
        [176, 0x1fffe0, 21], [177, 0x1fffe1, 21], [178, 0x3fffe0, 22], [179, 0x1fffe2, 21],
        [180, 0x7fffed, 23], [181, 0x3fffe1, 22], [182, 0x7fffee, 23], [183, 0x7fffef, 23],
        [184, 0xfffea, 20], [185, 0x3fffe2, 22], [186, 0x3fffe3, 22], [187, 0x3fffe4, 22],
        [188, 0x7ffff0, 23], [189, 0x3fffe5, 22], [190, 0x3fffe6, 22], [191, 0x7ffff1, 23],
        [192, 0x3ffffe0, 26], [193, 0x3ffffe1, 26], [194, 0xfffeb, 20], [195, 0x7fff1, 19],
        [196, 0x3fffe7, 22], [197, 0x7ffff2, 23], [198, 0x3fffe8, 22], [199, 0x1ffffec, 25],
        [200, 0x3ffffe2, 26], [201, 0x3ffffe3, 26], [202, 0x3ffffe4, 26], [203, 0x7ffffde, 27],
        [204, 0x7ffffdf, 27], [205, 0x3ffffe5, 26], [206, 0xfffff1, 24], [207, 0x1ffffed, 25],
        [208, 0x7fff2, 19], [209, 0x1fffe3, 21], [210, 0x3ffffe6, 26], [211, 0x7ffffe0, 27],
        [212, 0x7ffffe1, 27], [213, 0x3ffffe7, 26], [214, 0x7ffffe2, 27], [215, 0xfffff2, 24],
        [216, 0x1fffe4, 21], [217, 0x1fffe5, 21], [218, 0x3ffffe8, 26], [219, 0x3ffffe9, 26],
        [220, 0xffffffd, 28], [221, 0x7ffffe3, 27], [222, 0x7ffffe4, 27], [223, 0x7ffffe5, 27],
        [224, 0xfffec, 20], [225, 0xfffff3, 24], [226, 0xfffed, 20], [227, 0x1fffe6, 21],
        [228, 0x3fffe9, 22], [229, 0x1fffe7, 21], [230, 0x1fffe8, 21], [231, 0x7ffff3, 23],
        [232, 0x3fffea, 22], [233, 0x3fffeb, 22], [234, 0x1ffffee, 25], [235, 0x1ffffef, 25],
        [236, 0xfffff4, 24], [237, 0xfffff5, 24], [238, 0x3ffffea, 26], [239, 0x7ffff4, 23],
        [240, 0x3ffffeb, 26], [241, 0x7ffffe6, 27], [242, 0x3ffffec, 26], [243, 0x3ffffed, 26],
        [244, 0x7ffffe7, 27], [245, 0x7ffffe8, 27], [246, 0x7ffffe9, 27], [247, 0x7ffffea, 27],
        [248, 0x7ffffeb, 27], [249, 0xffffffe, 28], [250, 0x7ffffec, 27], [251, 0x7ffffed, 27],
        [252, 0x7ffffee, 27], [253, 0x7ffffef, 27], [254, 0x7fffff0, 27], [255, 0x3ffffee, 26],
        [256, 0x3fffffff, 30] // EOS
    ];

    // Build a lookup table organized by bit length
    const table = new Map();
    for (const [symbol, code, len] of codes) {
        table.set(`${code.toString(2).padStart(len, '0')}`, symbol);
    }
    return table;
}

/**
 * Decode Huffman-encoded string.
 * @param {Uint8Array} data - Huffman encoded bytes
 * @returns {string} Decoded string
 */
function decodeHuffman(data) {
    let bits = '';
    for (const byte of data) {
        bits += byte.toString(2).padStart(8, '0');
    }

    const result = [];
    let current = '';

    for (const bit of bits) {
        current += bit;
        const symbol = HUFFMAN_TABLE.get(current);
        if (symbol !== undefined) {
            if (symbol === 256) {
                // EOS - stop
                break;
            }
            result.push(String.fromCharCode(symbol));
            current = '';
        }
        // Max code length is 30 bits
        if (current.length > 30) {
            throw new Error('Invalid Huffman code');
        }
    }

    return result.join('');
}

/**
 * Decode an integer with the specified prefix bits.
 * @param {Uint8Array} data - Data to decode from
 * @param {number} offset - Starting offset
 * @param {number} prefixBits - Number of prefix bits (1-8)
 * @returns {{value: number, bytesRead: number}}
 */
function decodeInteger(data, offset, prefixBits) {
    const mask = (1 << prefixBits) - 1;
    let value = data[offset] & mask;
    let bytesRead = 1;

    if (value < mask) {
        return { value, bytesRead };
    }

    // Multi-byte integer
    let m = 0;
    while (offset + bytesRead < data.length) {
        const byte = data[offset + bytesRead];
        value += (byte & 0x7f) << m;
        m += 7;
        bytesRead++;

        if ((byte & 0x80) === 0) {
            break;
        }
    }

    return { value, bytesRead };
}

/**
 * Decode a string (with or without Huffman encoding).
 * @param {Uint8Array} data - Data to decode from
 * @param {number} offset - Starting offset
 * @returns {{value: string, bytesRead: number}}
 */
function decodeString(data, offset) {
    const huffman = (data[offset] & 0x80) !== 0;
    const { value: length, bytesRead: lenBytes } = decodeInteger(data, offset, 7);

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
 * HPACK decoder with dynamic table.
 */
export class HpackDecoder {
    /**
     * Create a new HPACK decoder.
     * @param {number|Object} maxTableSizeOrSnapshot - Max table size (number) or snapshot object
     */
    constructor(maxTableSizeOrSnapshot = 4096) {
        this.dynamicTable = [];
        this.maxTableSize = 4096;
        this.currentTableSize = 0;

        // If passed a snapshot object, initialize from it
        if (typeof maxTableSizeOrSnapshot === 'object' && maxTableSizeOrSnapshot !== null) {
            this.initFromSnapshot(maxTableSizeOrSnapshot);
        } else if (typeof maxTableSizeOrSnapshot === 'number') {
            this.maxTableSize = maxTableSizeOrSnapshot;
        }
    }

    /**
     * Initialize decoder from a snapshot (for mid-connection validation).
     * @param {Object} snapshot - HPACK table snapshot from forensic evidence
     * @param {Array<{name: string, value: string}>} snapshot.entries - Dynamic table entries
     * @param {number} snapshot.max_size - Maximum table size
     * @param {number} snapshot.current_size - Current table size
     */
    initFromSnapshot(snapshot) {
        if (!snapshot) return;

        this.maxTableSize = snapshot.max_size || 4096;
        this.currentTableSize = snapshot.current_size || 0;

        // Convert entries from {name, value} objects to [name, value] arrays
        if (snapshot.entries && Array.isArray(snapshot.entries)) {
            this.dynamicTable = snapshot.entries.map(entry => {
                if (Array.isArray(entry)) {
                    return entry;
                }
                return [entry.name || '', entry.value || ''];
            });

            // Recalculate current size if not provided
            if (!snapshot.current_size) {
                this.currentTableSize = this.dynamicTable.reduce(
                    (sum, [name, value]) => sum + 32 + name.length + value.length, 0
                );
            }
        }
    }

    /**
     * Get entry from combined static + dynamic table.
     * @param {number} index - 1-based index
     * @returns {[string, string]} [name, value]
     */
    getEntry(index) {
        if (index < 1) {
            throw new Error('Invalid index 0');
        }

        if (index <= 61) {
            return STATIC_TABLE[index];
        }

        const dynamicIndex = index - 62;
        if (dynamicIndex >= this.dynamicTable.length) {
            throw new Error(`Dynamic table index ${dynamicIndex} out of bounds (size: ${this.dynamicTable.length})`);
        }

        return this.dynamicTable[dynamicIndex];
    }

    /**
     * Add entry to dynamic table.
     * @param {string} name - Header name
     * @param {string} value - Header value
     */
    addEntry(name, value) {
        const entrySize = 32 + name.length + value.length;

        // Evict entries if needed
        while (this.currentTableSize + entrySize > this.maxTableSize && this.dynamicTable.length > 0) {
            const evicted = this.dynamicTable.pop();
            this.currentTableSize -= 32 + evicted[0].length + evicted[1].length;
        }

        if (entrySize <= this.maxTableSize) {
            this.dynamicTable.unshift([name, value]);
            this.currentTableSize += entrySize;
        }
    }

    /**
     * Update maximum table size.
     * @param {number} maxSize - New maximum size
     */
    setMaxTableSize(maxSize) {
        this.maxTableSize = maxSize;

        // Evict entries if needed
        while (this.currentTableSize > this.maxTableSize && this.dynamicTable.length > 0) {
            const evicted = this.dynamicTable.pop();
            this.currentTableSize -= 32 + evicted[0].length + evicted[1].length;
        }
    }

    /**
     * Decode an HPACK header block.
     * @param {Uint8Array} data - Encoded header block
     * @returns {Array<[string, string]>} Decoded headers
     */
    decode(data) {
        const headers = [];
        let offset = 0;

        while (offset < data.length) {
            const byte = data[offset];

            if ((byte & 0x80) !== 0) {
                // Indexed Header Field (Section 6.1)
                // Format: 1xxxxxxx
                const { value: index, bytesRead } = decodeInteger(data, offset, 7);
                offset += bytesRead;

                const [name, value] = this.getEntry(index);
                headers.push([name, value]);

            } else if ((byte & 0xc0) === 0x40) {
                // Literal Header Field with Incremental Indexing (Section 6.2.1)
                // Format: 01xxxxxx
                const { value: index, bytesRead: indexBytes } = decodeInteger(data, offset, 6);
                offset += indexBytes;

                let name;
                if (index === 0) {
                    const { value: n, bytesRead: nameBytes } = decodeString(data, offset);
                    name = n;
                    offset += nameBytes;
                } else {
                    [name] = this.getEntry(index);
                }

                const { value, bytesRead: valueBytes } = decodeString(data, offset);
                offset += valueBytes;

                headers.push([name, value]);
                this.addEntry(name, value);

            } else if ((byte & 0xf0) === 0x00) {
                // Literal Header Field without Indexing (Section 6.2.2)
                // Format: 0000xxxx
                const { value: index, bytesRead: indexBytes } = decodeInteger(data, offset, 4);
                offset += indexBytes;

                let name;
                if (index === 0) {
                    const { value: n, bytesRead: nameBytes } = decodeString(data, offset);
                    name = n;
                    offset += nameBytes;
                } else {
                    [name] = this.getEntry(index);
                }

                const { value, bytesRead: valueBytes } = decodeString(data, offset);
                offset += valueBytes;

                headers.push([name, value]);

            } else if ((byte & 0xf0) === 0x10) {
                // Literal Header Field Never Indexed (Section 6.2.3)
                // Format: 0001xxxx
                const { value: index, bytesRead: indexBytes } = decodeInteger(data, offset, 4);
                offset += indexBytes;

                let name;
                if (index === 0) {
                    const { value: n, bytesRead: nameBytes } = decodeString(data, offset);
                    name = n;
                    offset += nameBytes;
                } else {
                    [name] = this.getEntry(index);
                }

                const { value, bytesRead: valueBytes } = decodeString(data, offset);
                offset += valueBytes;

                headers.push([name, value]);

            } else if ((byte & 0xe0) === 0x20) {
                // Dynamic Table Size Update (Section 6.3)
                // Format: 001xxxxx
                const { value: maxSize, bytesRead } = decodeInteger(data, offset, 5);
                offset += bytesRead;
                this.setMaxTableSize(maxSize);

            } else {
                throw new Error(`Unknown HPACK opcode: 0x${byte.toString(16)}`);
            }
        }

        return headers;
    }

    /**
     * Reset the dynamic table.
     */
    reset() {
        this.dynamicTable = [];
        this.currentTableSize = 0;
    }
}

export { STATIC_TABLE, decodeHuffman };
