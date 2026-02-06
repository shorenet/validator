/**
 * HTTP/1.0 and HTTP/1.1 Parser
 * Parses HTTP request/response from raw bytes.
 */

/**
 * Parse an HTTP/1.x request from raw bytes.
 * @param {Uint8Array} data - Raw request data
 * @returns {{method: string, path: string, version: string, headers: Object, body: Uint8Array|null, bytesConsumed: number}}
 */
export function parseRequest(data) {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(data);
    const lines = text.split('\r\n');

    if (lines.length === 0) {
        throw new Error('Empty request');
    }

    // Parse request line: METHOD PATH HTTP/VERSION
    const requestLine = lines[0];
    const requestParts = requestLine.split(' ');

    if (requestParts.length < 3) {
        throw new Error(`Invalid request line: ${requestLine}`);
    }

    const method = requestParts[0];
    const path = requestParts[1];
    const version = requestParts.slice(2).join(' ');

    // Parse headers
    const headers = {};
    let headerEndIndex = 1;

    for (let i = 1; i < lines.length; i++) {
        const line = lines[i];
        if (line === '') {
            headerEndIndex = i;
            break;
        }

        const colonIndex = line.indexOf(':');
        if (colonIndex > 0) {
            const name = line.substring(0, colonIndex).trim().toLowerCase();
            const value = line.substring(colonIndex + 1).trim();
            headers[name] = value;
        }
    }

    // Calculate header end position in bytes
    let headerEndPos = 0;
    for (let i = 0; i <= headerEndIndex; i++) {
        headerEndPos += lines[i].length + 2; // +2 for \r\n
    }

    // Extract body if present
    let body = null;
    if (headerEndPos < data.length) {
        body = data.slice(headerEndPos);
    }

    return {
        method,
        path,
        version,
        headers,
        body,
        bytesConsumed: data.length
    };
}

/**
 * Parse an HTTP/1.x response from raw bytes.
 * @param {Uint8Array} data - Raw response data
 * @returns {{version: string, status: number, statusText: string, headers: Object, body: Uint8Array|null, bytesConsumed: number}}
 */
export function parseResponse(data) {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(data);
    const lines = text.split('\r\n');

    if (lines.length === 0) {
        throw new Error('Empty response');
    }

    // Parse status line: HTTP/VERSION STATUS STATUS_TEXT
    const statusLine = lines[0];
    const statusParts = statusLine.split(' ');

    if (statusParts.length < 2) {
        throw new Error(`Invalid status line: ${statusLine}`);
    }

    const version = statusParts[0];
    const status = parseInt(statusParts[1], 10);
    const statusText = statusParts.slice(2).join(' ');

    // Parse headers
    const headers = {};
    let headerEndIndex = 1;

    for (let i = 1; i < lines.length; i++) {
        const line = lines[i];
        if (line === '') {
            headerEndIndex = i;
            break;
        }

        const colonIndex = line.indexOf(':');
        if (colonIndex > 0) {
            const name = line.substring(0, colonIndex).trim().toLowerCase();
            const value = line.substring(colonIndex + 1).trim();
            headers[name] = value;
        }
    }

    // Calculate header end position in bytes
    let headerEndPos = 0;
    for (let i = 0; i <= headerEndIndex; i++) {
        headerEndPos += lines[i].length + 2; // +2 for \r\n
    }

    // Extract body if present
    let body = null;
    if (headerEndPos < data.length) {
        body = data.slice(headerEndPos);
    }

    return {
        version,
        status,
        statusText,
        headers,
        body,
        bytesConsumed: data.length
    };
}

/**
 * Decode chunked transfer encoding.
 * @param {Uint8Array} data - Chunked body data
 * @returns {Uint8Array} Decoded body
 */
export function decodeChunked(data) {
    const chunks = [];
    let offset = 0;
    const text = new TextDecoder('utf-8', { fatal: false }).decode(data);

    while (offset < data.length) {
        // Find chunk size line
        let lineEnd = text.indexOf('\r\n', offset);
        if (lineEnd === -1) break;

        const sizeLine = text.substring(offset, lineEnd);
        const chunkSize = parseInt(sizeLine, 16);

        if (isNaN(chunkSize) || chunkSize === 0) {
            break;
        }

        offset = lineEnd + 2; // Skip \r\n

        // Extract chunk data
        const chunkData = data.slice(offset, offset + chunkSize);
        chunks.push(chunkData);

        offset += chunkSize + 2; // Skip chunk data and trailing \r\n
    }

    // Combine chunks
    const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const result = new Uint8Array(totalLength);
    let resultOffset = 0;

    for (const chunk of chunks) {
        result.set(chunk, resultOffset);
        resultOffset += chunk.length;
    }

    return result;
}

/**
 * Determine content encoding from headers.
 * @param {Object} headers - HTTP headers
 * @returns {string|null} Encoding type or null
 */
export function getContentEncoding(headers) {
    const encoding = headers['content-encoding'];
    if (!encoding) return null;

    const normalized = encoding.toLowerCase().trim();
    if (normalized === 'gzip' || normalized === 'x-gzip') return 'gzip';
    if (normalized === 'deflate') return 'deflate';
    if (normalized === 'br') return 'br';
    if (normalized === 'zstd') return 'zstd';

    return null;
}

/**
 * Check if response uses chunked transfer encoding.
 * @param {Object} headers - HTTP headers
 * @returns {boolean}
 */
export function isChunked(headers) {
    const te = headers['transfer-encoding'];
    return te && te.toLowerCase().includes('chunked');
}

/**
 * Get content length from headers.
 * @param {Object} headers - HTTP headers
 * @returns {number|null}
 */
export function getContentLength(headers) {
    const cl = headers['content-length'];
    if (!cl) return null;

    const length = parseInt(cl, 10);
    return isNaN(length) ? null : length;
}
