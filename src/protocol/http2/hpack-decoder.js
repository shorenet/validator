/**
 * HPACK - HTTP/2 Header Compression (RFC 7541)
 * Pure JavaScript implementation for forensic validation.
 */

import { decodeHuffman } from '../../encoding/huffman.js';
import { decodeInteger } from '../../encoding/integer.js';

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
