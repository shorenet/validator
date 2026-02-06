/**
 * WebSocket Frame Parser (RFC 6455)
 * Parses WebSocket frames including support for permessage-deflate compression.
 *
 * Browser/Node.js compatible - uses pako for decompression
 */

import pako from 'pako';

/**
 * WebSocket opcodes.
 */
export const OPCODE = {
    CONTINUATION: 0x0,
    TEXT: 0x1,
    BINARY: 0x2,
    CLOSE: 0x8,
    PING: 0x9,
    PONG: 0xA
};

/**
 * Get opcode name.
 * @param {number} opcode
 * @returns {string}
 */
export function getOpcodeName(opcode) {
    switch (opcode) {
        case OPCODE.CONTINUATION: return 'Continuation';
        case OPCODE.TEXT: return 'Text';
        case OPCODE.BINARY: return 'Binary';
        case OPCODE.CLOSE: return 'Close';
        case OPCODE.PING: return 'Ping';
        case OPCODE.PONG: return 'Pong';
        default: return `Unknown(0x${opcode.toString(16)})`;
    }
}

/**
 * WebSocket close codes.
 */
export const CLOSE_CODE = {
    NORMAL: 1000,
    GOING_AWAY: 1001,
    PROTOCOL_ERROR: 1002,
    UNSUPPORTED_DATA: 1003,
    NO_STATUS: 1005,
    ABNORMAL: 1006,
    INVALID_PAYLOAD: 1007,
    POLICY_VIOLATION: 1008,
    MESSAGE_TOO_BIG: 1009,
    MANDATORY_EXTENSION: 1010,
    INTERNAL_ERROR: 1011,
    SERVICE_RESTART: 1012,
    TRY_AGAIN_LATER: 1013
};

/**
 * Get close code description.
 * @param {number} code
 * @returns {string}
 */
export function getCloseCodeDescription(code) {
    switch (code) {
        case CLOSE_CODE.NORMAL: return 'Normal Closure';
        case CLOSE_CODE.GOING_AWAY: return 'Going Away';
        case CLOSE_CODE.PROTOCOL_ERROR: return 'Protocol Error';
        case CLOSE_CODE.UNSUPPORTED_DATA: return 'Unsupported Data';
        case CLOSE_CODE.NO_STATUS: return 'No Status Received';
        case CLOSE_CODE.ABNORMAL: return 'Abnormal Closure';
        case CLOSE_CODE.INVALID_PAYLOAD: return 'Invalid Payload';
        case CLOSE_CODE.POLICY_VIOLATION: return 'Policy Violation';
        case CLOSE_CODE.MESSAGE_TOO_BIG: return 'Message Too Big';
        case CLOSE_CODE.MANDATORY_EXTENSION: return 'Mandatory Extension';
        case CLOSE_CODE.INTERNAL_ERROR: return 'Internal Error';
        case CLOSE_CODE.SERVICE_RESTART: return 'Service Restart';
        case CLOSE_CODE.TRY_AGAIN_LATER: return 'Try Again Later';
        default: return `Unknown (${code})`;
    }
}

/**
 * Parsed WebSocket frame.
 */
export class WebSocketFrame {
    /**
     * @param {Object} options
     */
    constructor(options) {
        this.fin = options.fin;
        this.rsv1 = options.rsv1;
        this.rsv2 = options.rsv2;
        this.rsv3 = options.rsv3;
        this.opcode = options.opcode;
        this.masked = options.masked;
        this.maskKey = options.maskKey;
        this.payload = options.payload;
        // Original compressed payload (before decompression), null if not compressed
        this.compressedPayload = options.compressedPayload || null;
    }

    /**
     * Whether this is a control frame.
     */
    get isControl() {
        return this.opcode >= 0x8;
    }

    /**
     * Whether this is a data frame.
     */
    get isData() {
        return this.opcode === OPCODE.TEXT ||
               this.opcode === OPCODE.BINARY ||
               this.opcode === OPCODE.CONTINUATION;
    }

    /**
     * Whether this frame indicates compression (RSV1 set).
     */
    get isCompressed() {
        return this.rsv1;
    }

    /**
     * Get payload as text (for text frames).
     * @returns {string|null}
     */
    asText() {
        if (this.opcode === OPCODE.TEXT || this.opcode === OPCODE.CONTINUATION) {
            return new TextDecoder('utf-8', { fatal: false }).decode(this.payload);
        }
        return null;
    }
}

/**
 * Parse a WebSocket frame from raw bytes.
 * @param {Uint8Array} data - Raw frame data
 * @returns {{frame: WebSocketFrame, bytesConsumed: number}|null} - Parsed frame or null if incomplete
 */
export function parseFrame(data) {
    if (data.length < 2) {
        return null;
    }

    const fin = (data[0] & 0x80) !== 0;
    const rsv1 = (data[0] & 0x40) !== 0;
    const rsv2 = (data[0] & 0x20) !== 0;
    const rsv3 = (data[0] & 0x10) !== 0;
    const opcode = data[0] & 0x0F;

    // Validate reserved opcodes
    if ((opcode >= 0x3 && opcode <= 0x7) || (opcode >= 0xB && opcode <= 0xF)) {
        throw new Error(`WebSocket reserved opcode 0x${opcode.toString(16)}`);
    }

    const masked = (data[1] & 0x80) !== 0;
    let payloadLen = data[1] & 0x7F;
    let offset = 2;

    // Extended payload length
    if (payloadLen === 126) {
        if (data.length < offset + 2) {
            return null;
        }
        payloadLen = (data[offset] << 8) | data[offset + 1];
        offset += 2;
    } else if (payloadLen === 127) {
        if (data.length < offset + 8) {
            return null;
        }
        // Note: JavaScript numbers can only safely handle 53 bits
        // For WebSocket, payloads > 2^53 are extremely rare
        payloadLen = 0;
        for (let i = 0; i < 8; i++) {
            payloadLen = payloadLen * 256 + data[offset + i];
        }
        offset += 8;
    }

    // Validate control frame constraints
    if (opcode >= 0x8) {
        if (payloadLen > 125) {
            throw new Error(`WebSocket control frame payload too large (${payloadLen} > 125)`);
        }
        if (!fin) {
            // Add diagnostic info to help debug parser misalignment
            const firstBytes = Array.from(data.slice(0, Math.min(20, data.length)))
                .map(b => `0x${b.toString(16).padStart(2, '0')}`)
                .join(' ');
            throw new Error(`WebSocket control frames cannot be fragmented (opcode=0x${opcode.toString(16)}, payloadLen=${payloadLen}, first 20 bytes: ${firstBytes})`);
        }
    }

    // Masking key
    let maskKey = null;
    if (masked) {
        if (data.length < offset + 4) {
            return null;
        }
        maskKey = data.slice(offset, offset + 4);
        offset += 4;
    }

    // Payload
    if (data.length < offset + payloadLen) {
        return null;
    }

    let payload = data.slice(offset, offset + payloadLen);

    // Unmask if necessary
    if (masked && maskKey) {
        payload = new Uint8Array(payload);
        for (let i = 0; i < payload.length; i++) {
            payload[i] ^= maskKey[i % 4];
        }
    }

    // Store original compressed payload before decompression (for validation)
    let compressedPayload = null;

    // Decompress if RSV1 is set (permessage-deflate)
    if (rsv1 && (opcode === 0x1 || opcode === 0x2)) {
        compressedPayload = payload;  // Keep original compressed bytes
        payload = decompressDeflate(payload);
    }

    const frame = new WebSocketFrame({
        fin,
        rsv1,
        rsv2,
        rsv3,
        opcode,
        masked,
        maskKey,
        payload,
        compressedPayload
    });

    return {
        frame,
        bytesConsumed: offset + payloadLen
    };
}

/**
 * Parse all frames from a buffer.
 * @param {Uint8Array} data
 * @returns {WebSocketFrame[]}
 */
export function parseFrames(data) {
    const frames = [];
    let offset = 0;

    while (offset < data.length) {
        try {
            const result = parseFrame(data.slice(offset));
            if (!result) {
                break;
            }
            frames.push(result.frame);
            offset += result.bytesConsumed;
        } catch (e) {
            // Add offset context to error
            const context = data.slice(Math.max(0, offset - 4), Math.min(data.length, offset + 16));
            const contextHex = Array.from(context).map(b => `0x${b.toString(16).padStart(2, '0')}`).join(' ');
            throw new Error(`${e.message} [at offset ${offset}/${data.length}, context: ${contextHex}]`);
        }
    }

    return frames;
}

/**
 * Parse a close frame payload.
 * @param {Uint8Array} payload
 * @returns {{code: number, reason: string}}
 */
export function parseClosePayload(payload) {
    if (payload.length >= 2) {
        const code = (payload[0] << 8) | payload[1];
        const reason = payload.length > 2
            ? new TextDecoder('utf-8', { fatal: false }).decode(payload.slice(2))
            : '';
        return { code, reason };
    }
    return { code: CLOSE_CODE.NO_STATUS, reason: '' };
}

/**
 * WebSocket message assembler.
 * Combines fragmented frames into complete messages.
 */
export class WebSocketAssembler {
    constructor() {
        this.messageType = null;
        this.fragments = [];
    }

    /**
     * Process a frame and return a complete message if ready.
     * @param {WebSocketFrame} frame
     * @returns {{type: string, data: Uint8Array}|null}
     */
    processFrame(frame) {
        // Control frames don't contribute to messages
        if (frame.isControl) {
            return null;
        }

        // Starting a new message?
        if (frame.opcode === OPCODE.TEXT) {
            this.messageType = 'text';
            this.fragments = [frame.payload];
        } else if (frame.opcode === OPCODE.BINARY) {
            this.messageType = 'binary';
            this.fragments = [frame.payload];
        } else if (frame.opcode === OPCODE.CONTINUATION) {
            this.fragments.push(frame.payload);
        }

        // Complete message?
        if (frame.fin && this.messageType) {
            // Combine fragments
            const totalLen = this.fragments.reduce((sum, f) => sum + f.length, 0);
            const combined = new Uint8Array(totalLen);
            let offset = 0;
            for (const fragment of this.fragments) {
                combined.set(fragment, offset);
                offset += fragment.length;
            }

            const result = {
                type: this.messageType,
                data: combined
            };

            // Reset state
            this.messageType = null;
            this.fragments = [];

            return result;
        }

        return null;
    }

    /**
     * Clear accumulated state.
     */
    clear() {
        this.messageType = null;
        this.fragments = [];
    }
}

/**
 * Parse permessage-deflate extension parameters.
 * @param {string} headerValue - Sec-WebSocket-Extensions header value
 * @returns {{serverMaxWindowBits: number, clientMaxWindowBits: number, serverNoContextTakeover: boolean, clientNoContextTakeover: boolean}|null}
 */
export function parsePerMessageDeflate(headerValue) {
    if (!headerValue.toLowerCase().includes('permessage-deflate')) {
        return null;
    }

    const params = {
        serverMaxWindowBits: 15,
        clientMaxWindowBits: 15,
        serverNoContextTakeover: false,
        clientNoContextTakeover: false
    };

    for (const part of headerValue.split(';').slice(1)) {
        const trimmed = part.trim();

        if (trimmed.startsWith('server_max_window_bits')) {
            const value = trimmed.split('=')[1];
            if (value) {
                const bits = parseInt(value.trim(), 10);
                if (bits >= 9 && bits <= 15) {
                    params.serverMaxWindowBits = bits;
                }
            }
        } else if (trimmed.startsWith('client_max_window_bits')) {
            const value = trimmed.split('=')[1];
            if (value) {
                const bits = parseInt(value.trim(), 10);
                if (bits >= 9 && bits <= 15) {
                    params.clientMaxWindowBits = bits;
                }
            }
        } else if (trimmed === 'server_no_context_takeover') {
            params.serverNoContextTakeover = true;
        } else if (trimmed === 'client_no_context_takeover') {
            params.clientNoContextTakeover = true;
        }
    }

    return params;
}

/**
 * Decompress permessage-deflate data synchronously using pako.
 *
 * NOTE: permessage-deflate with context takeover requires maintaining deflate
 * state across frames. We can only decompress frames where no_context_takeover
 * was negotiated OR when this is the first frame in the context. For frames
 * that fail decompression, we return the original data and let validation
 * fall back to parse-level.
 *
 * @param {Uint8Array} data - Compressed data
 * @returns {Uint8Array} - Decompressed data, or original if decompression fails
 */
export function decompressDeflate(data) {
    // Per RFC 7692, append trailing bytes that were stripped
    const withTrailer = new Uint8Array(data.length + 4);
    withTrailer.set(data);
    withTrailer.set([0x00, 0x00, 0xFF, 0xFF], data.length);

    try {
        return pako.inflateRaw(withTrailer);
    } catch (e) {
        // Decompression failed - likely due to context takeover requiring
        // state from prior frames. Return original data silently.
    }

    // Decompression failed, return as-is
    return data;
}

/**
 * Stateful WebSocket deflate decompressor for context takeover.
 *
 * When permessage-deflate is negotiated WITHOUT no_context_takeover,
 * the deflate sliding window is maintained across frames. This class
 * maintains that state to allow sequential decompression of frames.
 *
 * Uses pako.Inflate for stateful decompression.
 *
 * IMPORTANT: pako's onData callback doesn't fire for non-final deflate blocks
 * (BFINAL=0), which is what context takeover uses. We must extract data from
 * pako's internal strm.output buffer directly.
 */
export class WebSocketDeflateContext {
    constructor() {
        this._initInflater();
    }

    _initInflater() {
        this.inflater = new pako.Inflate({ raw: true });
        this.lastOutputPos = 0;
    }

    /**
     * Decompress a single frame, maintaining context for subsequent frames.
     * @param {Uint8Array} compressedData - Compressed frame payload (without trailer)
     * @returns {Promise<Uint8Array>} - Decompressed data
     */
    async decompress(compressedData) {
        // Per RFC 7692, append trailing bytes that were stripped
        const withTrailer = new Uint8Array(compressedData.length + 4);
        withTrailer.set(compressedData);
        withTrailer.set([0x00, 0x00, 0xFF, 0xFF], compressedData.length);

        // Track output position before push
        const beforePos = this.inflater.strm?.next_out || 0;

        this.inflater.push(withTrailer, pako.constants.Z_SYNC_FLUSH);
        if (this.inflater.err) {
            throw new Error(this.inflater.msg || 'Decompression error');
        }

        // Extract output from pako's internal buffer
        // For non-final blocks (BFINAL=0), onData doesn't fire but data is in strm.output
        const strm = this.inflater.strm;
        if (strm && strm.output && strm.next_out > beforePos) {
            const output = strm.output.slice(beforePos, strm.next_out);
            return new Uint8Array(output);
        }

        return new Uint8Array(0);
    }

    /**
     * Reset the decompression context.
     */
    reset() {
        this._initInflater();
    }
}

/**
 * Format a WebSocket message for display.
 * @param {Object} message - WebSocket message object
 * @returns {Object} - Formatted message details
 */
export function formatMessage(message) {
    const result = {
        type: message.message_type || message.type || 'unknown',
        direction: message.direction || 'unknown',
        timestamp: message.timestamp_us ? new Date(message.timestamp_us / 1000).toISOString() : null,
        size: 0,
        preview: ''
    };

    // Get the payload data
    let data = null;
    if (message.payload) {
        if (typeof message.payload === 'string') {
            // Base64 encoded
            const binary = atob(message.payload);
            data = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                data[i] = binary.charCodeAt(i);
            }
        } else if (message.payload instanceof Uint8Array) {
            data = message.payload;
        }
    }

    if (data) {
        result.size = data.length;

        if (result.type === 'text' || result.type === 'Text') {
            const text = new TextDecoder('utf-8', { fatal: false }).decode(data);
            result.preview = text.length > 200 ? text.substring(0, 200) + '...' : text;

            // Try to parse as JSON for prettier display
            try {
                const json = JSON.parse(text);
                result.isJson = true;
                result.jsonPreview = JSON.stringify(json, null, 2);
            } catch {
                result.isJson = false;
            }
        } else {
            // Binary data - show hex preview
            const hexBytes = Array.from(data.slice(0, 32))
                .map(b => b.toString(16).padStart(2, '0'))
                .join(' ');
            result.preview = hexBytes + (data.length > 32 ? '...' : '');
        }
    }

    return result;
}

/**
 * Validate a WebSocket message's hash if provided.
 * @param {Object} message - WebSocket message with payload and hash
 * @param {Function} sha256Fn - SHA256 hash function
 * @returns {Promise<{valid: boolean, computed: string, expected: string}>}
 */
export async function validateMessageHash(message, sha256Fn) {
    if (!message.payload_hash) {
        return { valid: true, computed: null, expected: null };
    }

    let data = null;
    if (typeof message.payload === 'string') {
        const binary = atob(message.payload);
        data = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            data[i] = binary.charCodeAt(i);
        }
    } else if (message.payload instanceof Uint8Array) {
        data = message.payload;
    }

    if (!data) {
        return { valid: false, computed: null, expected: message.payload_hash };
    }

    const hashBytes = await sha256Fn(data);
    const computed = Array.from(hashBytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

    const expected = message.payload_hash.toLowerCase();

    return {
        valid: computed === expected,
        computed,
        expected
    };
}
