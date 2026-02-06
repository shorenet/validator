/**
 * Mozilla Root CA Store
 *
 * This file contains the Mozilla root CA certificates for validating certificate chains
 * when CT lookup fails or for offline validation.
 *
 * Source: https://curl.se/ca/cacert.pem (extracted from Mozilla NSS)
 * This is the same root store used by Firefox.
 *
 * To update: Run `node scripts/update-mozilla-roots.js`
 *
 * Note: For now, this is a placeholder. The actual roots will be fetched dynamically
 * or bundled at build time. The chain-validator will attempt CT lookup first,
 * then fall back to this if available.
 */

// Placeholder - will be populated by build script or fetched dynamically
export const MOZILLA_ROOTS = [];

// URL to fetch roots dynamically (cached)
export const MOZILLA_ROOTS_URL = 'https://curl.se/ca/cacert.pem';

/**
 * Fetch and cache Mozilla roots dynamically.
 * This avoids bundling ~200KB of root certs in the main bundle.
 *
 * @returns {Promise<string[]>} Array of PEM-encoded root certificates
 */
let cachedRoots = null;
export async function fetchMozillaRoots() {
    if (cachedRoots) {
        return cachedRoots;
    }

    try {
        const response = await fetch(MOZILLA_ROOTS_URL, {
            // Cache for 24 hours
            cache: 'default',
        });

        if (!response.ok) {
            throw new Error(`Failed to fetch roots: ${response.status}`);
        }

        const pem = await response.text();

        // Split into individual certificates
        const certs = pem.split(/(?=-----BEGIN CERTIFICATE-----)/g)
            .filter(c => c.includes('BEGIN CERTIFICATE'))
            .map(c => c.trim());

        cachedRoots = certs;
        return certs;
    } catch (e) {
        console.warn(`Failed to fetch Mozilla roots: ${e.message}`);
        return MOZILLA_ROOTS; // Fall back to bundled (may be empty)
    }
}

/**
 * Convert PEM certificate to DER (base64).
 *
 * @param {string} pem - PEM-encoded certificate
 * @returns {string} Base64-encoded DER
 */
export function pemToDer(pem) {
    const lines = pem.split('\n');
    let base64 = '';
    let inCert = false;

    for (const line of lines) {
        if (line.includes('BEGIN CERTIFICATE')) {
            inCert = true;
            continue;
        }
        if (line.includes('END CERTIFICATE')) {
            break;
        }
        if (inCert) {
            base64 += line.trim();
        }
    }

    return base64;
}
