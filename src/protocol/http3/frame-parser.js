/**
 * HTTP/3 Frame Parser (RFC 9114)
 * Parses HTTP/3 frames over QUIC streams.
 */

import { QpackDecoder } from './qpack-decoder.js';
import { decodeVarint } from '../../encoding/varint.js';

/**
 * HTTP/3 frame types (RFC 9114 Section 7.2)
 */
export const FrameType = {
    DATA: 0x00,
    HEADERS: 0x01,
    CANCEL_PUSH: 0x03,
    SETTINGS: 0x04,
    PUSH_PROMISE: 0x05,
    GOAWAY: 0x07,
    MAX_PUSH_ID: 0x0d
};

/**
 * HTTP/3 settings identifiers (RFC 9114 Section 7.2.4.1)
 */
export const Settings = {
    QPACK_MAX_TABLE_CAPACITY: 0x01,
    MAX_FIELD_SECTION_SIZE: 0x06,
    QPACK_BLOCKED_STREAMS: 0x07
};

/**
 * QUIC stream types (RFC 9114 Section 6.2)
 */
export const StreamType = {
    CONTROL: 0x00,
    PUSH: 0x01,
    QPACK_ENCODER: 0x02,
    QPACK_DECODER: 0x03
};

// decodeVarint now imported from shared encoding module

/**
 * Parse an HTTP/3 frame.
 * @param {Uint8Array} data - Data containing frame
 * @param {number} offset - Starting offset
 * @returns {{type: number, payload: Uint8Array, bytesRead: number}|null}
 */
export function parseFrame(data, offset = 0) {
    if (offset >= data.length) {
        return null;
    }

    // Frame type (varint)
    const { value: type, bytesRead: typeBytes } = decodeVarint(data, offset);
    offset += typeBytes;

    // Frame length (varint)
    const { value: length, bytesRead: lengthBytes } = decodeVarint(data, offset);
    offset += lengthBytes;

    // Sanity check: reject frames claiming to be larger than 10MB
    // This prevents hangs from corrupted length fields
    if (length > 10 * 1024 * 1024) {
        return null;
    }

    // Check if we have enough data
    if (offset + length > data.length) {
        return null; // Incomplete frame
    }

    const payload = data.slice(offset, offset + length);

    return {
        type,
        payload,
        bytesRead: typeBytes + lengthBytes + length
    };
}

/**
 * Parse all HTTP/3 frames from stream data.
 * @param {Uint8Array} data - Stream data
 * @param {number} maxFrames - Maximum number of frames to parse (safety limit)
 * @returns {Array<{type: number, payload: Uint8Array}>}
 */
export function parseFrames(data, maxFrames = 10000) {
    const frames = [];
    let offset = 0;

    while (offset < data.length && frames.length < maxFrames) {
        const frame = parseFrame(data, offset);
        if (!frame) break;

        frames.push({ type: frame.type, payload: frame.payload });
        offset += frame.bytesRead;
    }

    return frames;
}

/**
 * Parse SETTINGS frame payload.
 * @param {Uint8Array} payload
 * @returns {Map<number, number>}
 */
export function parseSettings(payload) {
    const settings = new Map();
    let offset = 0;

    while (offset < payload.length) {
        const { value: id, bytesRead: idBytes } = decodeVarint(payload, offset);
        offset += idBytes;

        const { value, bytesRead: valueBytes } = decodeVarint(payload, offset);
        offset += valueBytes;

        settings.set(id, value);
    }

    return settings;
}

/**
 * HTTP/3 stream for tracking request/response.
 */
export class Http3Stream {
    constructor(streamId) {
        this.streamId = streamId;
        this.requestHeaders = null;
        this.responseHeaders = null;
        this.requestData = [];
        this.responseData = [];
    }

    /**
     * Combine data frames into single body.
     * @param {boolean} isRequest
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
 * HTTP/3 connection parser.
 * Manages QPACK state and stream parsing.
 */
export class Http3Parser {
    constructor(maxTableCapacity = 4096) {
        this.qpackDecoder = new QpackDecoder(maxTableCapacity);
        this.streams = new Map();
        this.settings = new Map();
    }

    /**
     * Get or create stream.
     * @param {number} streamId
     * @returns {Http3Stream}
     */
    getStream(streamId) {
        if (!this.streams.has(streamId)) {
            this.streams.set(streamId, new Http3Stream(streamId));
        }
        return this.streams.get(streamId);
    }

    /**
     * Process QPACK encoder stream data.
     * @param {Uint8Array} data
     * @returns {number} Bytes consumed
     */
    processEncoderStream(data) {
        return this.qpackDecoder.processEncoderStream(data);
    }

    /**
     * Process control stream data.
     * @param {Uint8Array} data
     */
    processControlStream(data) {
        const frames = parseFrames(data);

        for (const frame of frames) {
            if (frame.type === FrameType.SETTINGS) {
                const settings = parseSettings(frame.payload);
                for (const [id, value] of settings) {
                    this.settings.set(id, value);
                    if (id === Settings.QPACK_MAX_TABLE_CAPACITY) {
                        this.qpackDecoder.setMaxCapacity(value);
                    }
                }
            }
        }
    }

    /**
     * Process request stream data.
     * @param {number} streamId
     * @param {Uint8Array} data
     */
    processRequestStream(streamId, data) {
        const stream = this.getStream(streamId);
        const frames = parseFrames(data);

        for (const frame of frames) {
            switch (frame.type) {
                case FrameType.HEADERS:
                    const headers = this.qpackDecoder.decode(frame.payload, true);

                    // Check if this is a response (has :status)
                    const isResponse = headers.some(([name]) => name === ':status');

                    if (isResponse) {
                        stream.responseHeaders = headers;
                    } else {
                        stream.requestHeaders = headers;
                    }
                    break;

                case FrameType.DATA:
                    if (stream.responseHeaders) {
                        stream.responseData.push(frame.payload);
                    } else {
                        stream.requestData.push(frame.payload);
                    }
                    break;
            }
        }
    }

    /**
     * Parse request stream data and extract transaction.
     * @param {number} streamId
     * @param {Uint8Array} clientData - Data from client
     * @param {Uint8Array} serverData - Data from server
     * @returns {Http3Stream}
     */
    parseStream(streamId, clientData, serverData) {
        const stream = this.getStream(streamId);

        // Process client data (request)
        if (clientData && clientData.length > 0) {
            const frames = parseFrames(clientData);
            for (const frame of frames) {
                if (frame.type === FrameType.HEADERS) {
                    stream.requestHeaders = this.qpackDecoder.decode(frame.payload, true);
                } else if (frame.type === FrameType.DATA) {
                    stream.requestData.push(frame.payload);
                }
            }
        }

        // Process server data (response)
        if (serverData && serverData.length > 0) {
            const frames = parseFrames(serverData);
            for (const frame of frames) {
                if (frame.type === FrameType.HEADERS) {
                    stream.responseHeaders = this.qpackDecoder.decode(frame.payload, true);
                } else if (frame.type === FrameType.DATA) {
                    stream.responseData.push(frame.payload);
                }
            }
        }

        return stream;
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

    /**
     * Get QPACK decoder state for debugging.
     */
    getQpackState() {
        return this.qpackDecoder.getState();
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
        [FrameType.CANCEL_PUSH]: 'CANCEL_PUSH',
        [FrameType.SETTINGS]: 'SETTINGS',
        [FrameType.PUSH_PROMISE]: 'PUSH_PROMISE',
        [FrameType.GOAWAY]: 'GOAWAY',
        [FrameType.MAX_PUSH_ID]: 'MAX_PUSH_ID'
    };
    return names[type] || `UNKNOWN(0x${type.toString(16)})`;
}

/**
 * Get stream type name.
 * @param {number} type
 * @returns {string}
 */
export function getStreamTypeName(type) {
    const names = {
        [StreamType.CONTROL]: 'Control',
        [StreamType.PUSH]: 'Push',
        [StreamType.QPACK_ENCODER]: 'QPACK Encoder',
        [StreamType.QPACK_DECODER]: 'QPACK Decoder'
    };
    return names[type] || `Unknown(0x${type.toString(16)})`;
}
