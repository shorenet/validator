/**
 * TLS record layer parsing (RFC 8446 Section 5)
 *
 * Parses TLS records from a byte stream without decryption.
 * Handles both TLS 1.2 and TLS 1.3 record formats.
 */

/**
 * TLS content types.
 */
export const TLS_CONTENT_TYPE = {
    CHANGE_CIPHER_SPEC: 20,
    ALERT: 21,
    HANDSHAKE: 22,
    APPLICATION_DATA: 23
};

/**
 * TLS handshake message types.
 */
export const TLS_HANDSHAKE_TYPE = {
    CLIENT_HELLO: 1,
    SERVER_HELLO: 2,
    NEW_SESSION_TICKET: 4,
    ENCRYPTED_EXTENSIONS: 8,
    CERTIFICATE: 11,
    CERTIFICATE_REQUEST: 13,
    CERTIFICATE_VERIFY: 15,
    FINISHED: 20
};

/**
 * Parse a single TLS record from data at given offset.
 *
 * @param {Uint8Array} data - Raw bytes
 * @param {number} offset - Offset to start parsing
 * @returns {{type: number, version: number, data: Uint8Array, raw: Uint8Array, length: number}|null}
 */
export function parseRecord(data, offset = 0) {
    if (offset + 5 > data.length) return null;

    const type = data[offset];
    const version = (data[offset + 1] << 8) | data[offset + 2];
    const length = (data[offset + 3] << 8) | data[offset + 4];

    if (offset + 5 + length > data.length) return null;

    return {
        type,
        version,
        data: data.slice(offset + 5, offset + 5 + length),
        raw: data.slice(offset, offset + 5 + length),
        length: 5 + length
    };
}

/**
 * Parse all TLS records from a byte stream.
 *
 * @param {Uint8Array} data - Raw bytes containing TLS records
 * @returns {Array<{type: number, version: number, data: Uint8Array, raw: Uint8Array}>}
 */
export function parseRecords(data) {
    const records = [];
    let offset = 0;

    while (offset + 5 <= data.length) {
        const type = data[offset];
        const version = (data[offset + 1] << 8) | data[offset + 2];
        const length = (data[offset + 3] << 8) | data[offset + 4];

        if (offset + 5 + length > data.length) {
            break;
        }

        records.push({
            type,
            version,
            data: data.slice(offset + 5, offset + 5 + length),
            raw: data.slice(offset, offset + 5 + length)
        });

        offset += 5 + length;
    }

    return records;
}
