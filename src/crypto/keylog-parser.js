/**
 * NSS Key Log Format parser (SSLKEYLOGFILE)
 * Parses TLS 1.2 and TLS 1.3 key material from NSS keylog format.
 *
 * Format: Each line contains a label followed by hex-encoded values
 * TLS 1.2: CLIENT_RANDOM <client_random> <master_secret>
 * TLS 1.3: CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
 *          SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
 *          CLIENT_TRAFFIC_SECRET_0 <client_random> <secret>
 *          SERVER_TRAFFIC_SECRET_0 <client_random> <secret>
 *          EXPORTER_SECRET <client_random> <secret>
 */

/**
 * Parse keylog string into structured object.
 *
 * @param {string} keylogStr - NSS keylog format string
 * @returns {Object|null} Parsed keylog with {version, keys, client_random?} or null if invalid
 */
export function parseKeylog(keylogStr) {
    if (!keylogStr) return null;

    // Already parsed - pass through
    if (typeof keylogStr === 'object') return keylogStr;

    const keys = {};
    let clientRandom = null;
    const lines = keylogStr.split('\n');

    for (const line of lines) {
        const trimmed = line.trim();

        // Skip empty lines and comments
        if (!trimmed || trimmed.startsWith('#')) continue;

        const parts = trimmed.split(/\s+/);
        if (parts.length < 3) continue;

        const label = parts[0].toLowerCase();

        // TLS 1.2 format: CLIENT_RANDOM <client_random> <master_secret>
        if (label === 'client_random' && parts.length === 3) {
            clientRandom = parts[1];
            keys.master_secret = parts[2];
        } else {
            // TLS 1.3 format: <LABEL> <client_random> <secret>
            keys[label] = parts[2];
        }
    }

    // Detect TLS version based on available keys
    let version;
    if (keys.client_traffic_secret_0 || keys.server_traffic_secret_0 ||
        keys.client_handshake_traffic_secret || keys.server_handshake_traffic_secret) {
        version = 'TLS13';
    } else if (clientRandom && keys.master_secret) {
        version = 'TLS12';
    } else {
        // No valid keys found
        return null;
    }

    const result = { version, keys };
    if (version === 'TLS12') {
        result.client_random = clientRandom;
    }
    return result;
}

/**
 * Get a specific key by client random and label.
 * Helper for looking up keys in parsed keylog.
 *
 * @param {Object} keylog - Parsed keylog object
 * @param {string} clientRandom - Client random (hex string)
 * @param {string} label - Key label (e.g., 'client_traffic_secret_0')
 * @returns {string|null} Hex-encoded key or null if not found
 */
export function getKeyByClientRandom(keylog, clientRandom, label) {
    if (!keylog || !keylog.keys) return null;

    const normalizedLabel = label.toLowerCase();
    return keylog.keys[normalizedLabel] || null;
}

/**
 * Check if keylog contains TLS 1.3 keys.
 *
 * @param {Object} keylog - Parsed keylog object
 * @returns {boolean} True if TLS 1.3 keys are present
 */
export function isTls13(keylog) {
    return keylog && keylog.version === 'TLS13';
}

/**
 * Check if keylog contains TLS 1.2 keys.
 *
 * @param {Object} keylog - Parsed keylog object
 * @returns {boolean} True if TLS 1.2 keys are present
 */
export function isTls12(keylog) {
    return keylog && keylog.version === 'TLS12';
}
