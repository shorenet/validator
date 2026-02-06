/**
 * Transaction Normalizer
 * Normalizes transactions for validation and comparison
 *
 * Accepts a `claimed` object (constructed at the validation boundary)
 * with `claimed.tls` for certificate info. For backward compatibility
 * with old data, falls back to `claimed.forensic_evidence?.certificate_info`.
 */

import { normalizeHeaders } from '../reconstruction/shared.js';

/**
 * Normalize a transaction or message for validation.
 * Uses `claimed.tls` for certificate info (new format),
 * with fallback to `claimed.forensic_evidence?.certificate_info` (old format).
 *
 * @param {Object} claimed - Claimed data object (id, protocol, request, response, connection, tls, etc.)
 * @returns {Object} Normalized transaction/message
 */
export function normalizeForValidation(claimed) {
    // New format: claimed.tls; backward compat: forensic_evidence.certificate_info
    const certInfo = claimed.tls || claimed.forensic_evidence?.certificate_info || null;

    // For WebSocket messages (have message_type field)
    if (claimed.message_type) {
        // For compressed messages: keep compressed_payload (verifiable raw bytes),
        // exclude payload/text (unverifiable without sliding window decompression context)
        const isCompressed = !!claimed.compressed_payload;

        const normalized = {
            id: claimed.id,
            message_type: claimed.message_type,
            direction: claimed.direction,
            close_code: claimed.close_code || null,
            close_reason: claimed.close_reason || null,
            url: claimed.url,
            connection: claimed.connection,
            certificate_info: certInfo,
        };

        // Only include payload/text if NOT compressed (verifiable)
        if (!isCompressed) {
            if (claimed.payload) normalized.payload = claimed.payload;
            if (claimed.text) normalized.text = claimed.text;
        }

        // Include compressed_payload if present
        if (claimed.compressed_payload) {
            normalized.compressed_payload = claimed.compressed_payload;
        }

        return normalized;
    }

    // For HTTP transactions
    return {
        id: claimed.id,
        protocol: claimed.protocol,
        request: claimed.request ? {
            method: claimed.request.method,
            url: claimed.request.url,
            headers: normalizeHeaders(claimed.request.headers),
        } : null,
        response: claimed.response ? {
            status: claimed.response.status,
            headers: normalizeHeaders(claimed.response.headers),
        } : null,
        connection: claimed.connection,
        certificate_info: certInfo,
    };
}
