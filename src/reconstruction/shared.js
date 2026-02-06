/**
 * Shared reconstruction helpers
 */

/**
 * Build a normalized transaction object from parsed data.
 *
 * @param {Object} claimed - Claimed identity fields (id, protocol, connection, request)
 * @param {Object|null} extractedCertInfo - Certificate info EXTRACTED from decrypted handshake (not claimed)
 * @param {Object} parsedRequest - Request parsed from decrypted evidence
 * @param {Object|null} parsedResponse - Response parsed from decrypted evidence
 * @returns {Object} Normalized transaction for hash comparison
 */
export function buildNormalizedTransaction(claimed, extractedCertInfo, parsedRequest, parsedResponse) {
    // Build URL from parsed components
    let url;
    if (parsedRequest.scheme && parsedRequest.authority && parsedRequest.path) {
        url = `${parsedRequest.scheme}://${parsedRequest.authority}${parsedRequest.path}`;
    } else if (parsedRequest.authority && parsedRequest.path) {
        url = `https://${parsedRequest.authority}${parsedRequest.path}`;
    } else {
        // Fall back to claimed URL structure
        url = claimed.request?.url || '';
    }

    // Build normalized transaction
    const normalized = {
        // Core identification (from claimed — these are assigned IDs, not wire data)
        id: claimed.id,
        protocol: claimed.protocol,

        // Connection info (from claimed)
        connection: claimed.connection ? {
            id: claimed.connection.id,
            client_addr: claimed.connection.client_addr,
            server_addr: claimed.connection.server_addr,
        } : null,

        // Request reconstructed from evidence
        request: {
            method: parsedRequest.method,
            url: url,
            headers: normalizeHeaders(parsedRequest.headers),
        },

        // Response reconstructed from evidence
        response: parsedResponse ? {
            status: parsedResponse.status,
            headers: normalizeHeaders(parsedResponse.headers),
        } : null,

        // Certificate info from EXTRACTED data (what the validator decrypted from handshake)
        certificate_info: extractedCertInfo ? {
            sni: extractedCertInfo.sni,
            tls_version: extractedCertInfo.tls_version,
            alpn: extractedCertInfo.alpn,
            cipher_suite: extractedCertInfo.cipher_suite,
            certificate_chain: extractedCertInfo.certificate_chain,
        } : null,
    };

    return normalized;
}

/**
 * Normalize headers for comparison.
 * Removes pseudo-headers (: prefix) and lowercases names.
 */
export function normalizeHeaders(headers) {
    // Compare like-for-like: no lowercasing, no removal of pseudo-headers
    // Sort by key to ensure consistent ordering for hash comparison
    if (!headers) return {};
    const sorted = {};
    for (const key of Object.keys(headers).sort()) {
        sorted[key] = headers[key];
    }
    return sorted;
}
