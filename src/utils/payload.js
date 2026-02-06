/**
 * Payload extraction utilities.
 *
 * Since framing is now stripped at capture time in the Rust pipeline,
 * packets are always transport payload (TLS records or QUIC packets).
 */

/**
 * Extract TLS/QUIC payload from raw packet data.
 *
 * Since framing is now stripped at capture time in the Rust pipeline,
 * packets are always transport payload (TLS records or QUIC packets).
 *
 * @param {Uint8Array} data - Raw packet bytes (already transport payload)
 * @returns {Uint8Array|null} The payload data, or null if empty
 */
export function extractTlsPayload(data) {
    if (!data || data.length === 0) return null;
    return data;
}
