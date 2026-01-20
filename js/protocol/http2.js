/**
 * HTTP/2 Frame Parser (RFC 7540)
 * Parses HTTP/2 frames and extracts headers/data.
 */

import { HpackDecoder } from './hpack.js';

/**
 * HTTP/2 frame types (RFC 7540 Section 6)
 */
export const FrameType = {
    DATA: 0x0,
    HEADERS: 0x1,
    PRIORITY: 0x2,
    RST_STREAM: 0x3,
    SETTINGS: 0x4,
    PUSH_PROMISE: 0x5,
    PING: 0x6,
    GOAWAY: 0x7,
    WINDOW_UPDATE: 0x8,
    CONTINUATION: 0x9
};

/**
 * HTTP/2 frame flags
 */
export const FrameFlags = {
    END_STREAM: 0x1,
    END_HEADERS: 0x4,
    PADDED: 0x8,
    PRIORITY: 0x20
};

/**
 * HTTP/2 settings identifiers
 */
export const Settings = {
    HEADER_TABLE_SIZE: 0x1,
    ENABLE_PUSH: 0x2,
    MAX_CONCURRENT_STREAMS: 0x3,
    INITIAL_WINDOW_SIZE: 0x4,
    MAX_FRAME_SIZE: 0x5,
    MAX_HEADER_LIST_SIZE: 0x6
};

/**
 * Parse an HTTP/2 frame header.
 * @param {Uint8Array} data - Data containing frame header (at least 9 bytes)
 * @returns {{length: number, type: number, flags: number, streamId: number}}
 */
export function parseFrameHeader(data) {
    if (data.length < 9) {
        throw new Error('Frame header too short');
    }

    const length = (data[0] << 16) | (data[1] << 8) | data[2];
    const type = data[3];
    const flags = data[4];
    // Stream ID is 31 bits (ignore reserved bit)
    const streamId = ((data[5] & 0x7f) << 24) | (data[6] << 16) | (data[7] << 8) | data[8];

    return { length, type, flags, streamId };
}

/**
 * Parse all HTTP/2 frames from raw data.
 * @param {Uint8Array} data - Raw frame data
 * @returns {Array<{type: number, flags: number, streamId: number, payload: Uint8Array}>}
 */
export function parseFrames(data) {
    const frames = [];
    let offset = 0;

    while (offset + 9 <= data.length) {
        const header = parseFrameHeader(data.slice(offset));

        if (offset + 9 + header.length > data.length) {
            // Incomplete frame
            break;
        }

        const payload = data.slice(offset + 9, offset + 9 + header.length);

        frames.push({
            type: header.type,
            flags: header.flags,
            streamId: header.streamId,
            payload
        });

        offset += 9 + header.length;
    }

    return frames;
}

/**
 * Extract header block from HEADERS frame (handling padding and priority).
 * @param {Uint8Array} payload - Frame payload
 * @param {number} flags - Frame flags
 * @returns {Uint8Array} Header block fragment
 */
export function extractHeaderBlock(payload, flags) {
    let offset = 0;
    let headerBlockLength = payload.length;

    // Handle padding
    if (flags & FrameFlags.PADDED) {
        const padLength = payload[0];
        offset += 1;
        headerBlockLength -= 1 + padLength;
    }

    // Handle priority
    if (flags & FrameFlags.PRIORITY) {
        offset += 5; // Stream dependency (4) + weight (1)
        headerBlockLength -= 5;
    }

    return payload.slice(offset, offset + headerBlockLength);
}

/**
 * Parse SETTINGS frame payload.
 * @param {Uint8Array} payload - Frame payload
 * @returns {Map<number, number>} Settings map
 */
export function parseSettings(payload) {
    const settings = new Map();

    for (let i = 0; i + 6 <= payload.length; i += 6) {
        const id = (payload[i] << 8) | payload[i + 1];
        const value = (payload[i + 2] << 24) | (payload[i + 3] << 16) |
                      (payload[i + 4] << 8) | payload[i + 5];
        settings.set(id, value >>> 0); // Convert to unsigned
    }

    return settings;
}

/**
 * HTTP/2 stream state for parsing.
 */
export class Http2Stream {
    constructor(streamId) {
        this.streamId = streamId;
        this.requestHeaders = null;
        this.responseHeaders = null;
        this.requestData = [];
        this.responseData = [];
        this.requestComplete = false;
        this.responseComplete = false;
    }

    /**
     * Combine data frames into a single body.
     * @param {boolean} isRequest - True for request, false for response
     * @returns {Uint8Array}
     */
    getBody(isRequest) {
        const frames = isRequest ? this.requestData : this.responseData;
        const totalLength = frames.reduce((sum, f) => sum + f.length, 0);
        const result = new Uint8Array(totalLength);
        let offset = 0;

        for (const frame of frames) {
            result.set(frame, offset);
            offset += frame.length;
        }

        return result;
    }
}

/**
 * HTTP/2 connection parser.
 * Handles multiple streams and HPACK state.
 */
export class Http2Parser {
    constructor() {
        this.hpackDecoder = new HpackDecoder(4096);
        this.streams = new Map();
        this.settings = new Map();
        this.continuationStream = null;
        this.continuationBuffer = [];
    }

    /**
     * Get or create stream.
     * @param {number} streamId
     * @returns {Http2Stream}
     */
    getStream(streamId) {
        if (!this.streams.has(streamId)) {
            this.streams.set(streamId, new Http2Stream(streamId));
        }
        return this.streams.get(streamId);
    }

    /**
     * Process a single frame.
     * @param {{type: number, flags: number, streamId: number, payload: Uint8Array}} frame
     */
    processFrame(frame) {
        switch (frame.type) {
            case FrameType.HEADERS:
                this.processHeaders(frame);
                break;

            case FrameType.CONTINUATION:
                this.processContinuation(frame);
                break;

            case FrameType.DATA:
                this.processData(frame);
                break;

            case FrameType.SETTINGS:
                if (frame.streamId === 0 && !(frame.flags & 0x1)) {
                    // Not an ACK
                    const settings = parseSettings(frame.payload);
                    for (const [id, value] of settings) {
                        this.settings.set(id, value);
                        if (id === Settings.HEADER_TABLE_SIZE) {
                            this.hpackDecoder.setMaxTableSize(value);
                        }
                    }
                }
                break;

            case FrameType.PUSH_PROMISE:
                // Extract promised stream ID and headers
                // For now, we don't fully support push promise
                break;
        }
    }

    /**
     * Process HEADERS frame.
     */
    processHeaders(frame) {
        const headerBlock = extractHeaderBlock(frame.payload, frame.flags);

        if (frame.flags & FrameFlags.END_HEADERS) {
            // Complete header block
            const headers = this.hpackDecoder.decode(headerBlock);
            const stream = this.getStream(frame.streamId);

            // Determine if request or response based on :status pseudo-header
            const isResponse = headers.some(([name]) => name === ':status');

            if (isResponse) {
                stream.responseHeaders = headers;
                if (frame.flags & FrameFlags.END_STREAM) {
                    stream.responseComplete = true;
                }
            } else {
                stream.requestHeaders = headers;
                if (frame.flags & FrameFlags.END_STREAM) {
                    stream.requestComplete = true;
                }
            }
        } else {
            // Need CONTINUATION frames
            this.continuationStream = frame.streamId;
            this.continuationBuffer = [headerBlock];
        }
    }

    /**
     * Process CONTINUATION frame.
     */
    processContinuation(frame) {
        if (frame.streamId !== this.continuationStream) {
            throw new Error('CONTINUATION frame for wrong stream');
        }

        this.continuationBuffer.push(frame.payload);

        if (frame.flags & FrameFlags.END_HEADERS) {
            // Combine all header block fragments
            const totalLength = this.continuationBuffer.reduce((sum, b) => sum + b.length, 0);
            const headerBlock = new Uint8Array(totalLength);
            let offset = 0;

            for (const buf of this.continuationBuffer) {
                headerBlock.set(buf, offset);
                offset += buf.length;
            }

            const headers = this.hpackDecoder.decode(headerBlock);
            const stream = this.getStream(frame.streamId);

            const isResponse = headers.some(([name]) => name === ':status');
            if (isResponse) {
                stream.responseHeaders = headers;
            } else {
                stream.requestHeaders = headers;
            }

            this.continuationStream = null;
            this.continuationBuffer = [];
        }
    }

    /**
     * Process DATA frame.
     */
    processData(frame) {
        const stream = this.getStream(frame.streamId);

        // Remove padding if present
        let payload = frame.payload;
        if (frame.flags & FrameFlags.PADDED) {
            const padLength = payload[0];
            payload = payload.slice(1, payload.length - padLength);
        }

        // Determine if request or response data based on stream state
        if (!stream.responseHeaders) {
            stream.requestData.push(payload);
            if (frame.flags & FrameFlags.END_STREAM) {
                stream.requestComplete = true;
            }
        } else {
            stream.responseData.push(payload);
            if (frame.flags & FrameFlags.END_STREAM) {
                stream.responseComplete = true;
            }
        }
    }

    /**
     * Parse all frames and return streams with complete transactions.
     * @param {Uint8Array} data - Raw HTTP/2 frame data
     * @returns {Map<number, Http2Stream>}
     */
    parse(data) {
        const frames = parseFrames(data);
        for (const frame of frames) {
            this.processFrame(frame);
        }
        return this.streams;
    }

    /**
     * Convert headers array to object.
     * @param {Array<[string, string]>} headers
     * @returns {Object}
     */
    static headersToObject(headers) {
        const result = {};
        for (const [name, value] of headers) {
            if (name in result) {
                // Combine multiple values with comma
                result[name] = result[name] + ', ' + value;
            } else {
                result[name] = value;
            }
        }
        return result;
    }

    /**
     * Get pseudo-headers from headers array.
     * @param {Array<[string, string]>} headers
     * @returns {{method?: string, path?: string, scheme?: string, authority?: string, status?: string}}
     */
    static getPseudoHeaders(headers) {
        const result = {};
        for (const [name, value] of headers) {
            if (name.startsWith(':')) {
                result[name.substring(1)] = value;
            }
        }
        return result;
    }
}

/**
 * Get frame type name.
 * @param {number} type
 * @returns {string}
 */
export function getFrameTypeName(type) {
    const names = {
        [FrameType.DATA]: 'DATA',
        [FrameType.HEADERS]: 'HEADERS',
        [FrameType.PRIORITY]: 'PRIORITY',
        [FrameType.RST_STREAM]: 'RST_STREAM',
        [FrameType.SETTINGS]: 'SETTINGS',
        [FrameType.PUSH_PROMISE]: 'PUSH_PROMISE',
        [FrameType.PING]: 'PING',
        [FrameType.GOAWAY]: 'GOAWAY',
        [FrameType.WINDOW_UPDATE]: 'WINDOW_UPDATE',
        [FrameType.CONTINUATION]: 'CONTINUATION'
    };
    return names[type] || `UNKNOWN(${type})`;
}
