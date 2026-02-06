/**
 * HTTP/2 Frame Parser (RFC 9113)
 *
 * Parses HTTP/2 frames from a byte stream.
 * Handles frame headers, padding, priority, and settings.
 */

/**
 * HTTP/2 frame types (RFC 9113 Section 6)
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
 * Get human-readable frame type name.
 * @param {number} type - Frame type value
 * @returns {string} Frame type name
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
