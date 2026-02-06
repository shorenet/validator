/**
 * Certificate Chain Validator
 *
 * Validates certificate chains using:
 * 1. Certificate Transparency logs (crt.sh) - proves cert was issued by a real CA
 * 2. Chain signature verification - proves each cert is signed by its issuer
 * 3. SNI verification - proves certificate is valid for the claimed hostname
 *
 * This module is designed to work in both Node.js and browser environments.
 * Uses @peculiar/x509 for certificate parsing (works with WebCrypto).
 */

import { base64ToBytes } from '../crypto/hash.js';
import { fetchMozillaRoots, pemToDer } from './mozilla-roots.js';
// Dynamic import for @peculiar/x509 to support both Node.js and browser
// In browser, load from esm.sh CDN; in Node.js, use npm package
let x509Module = null;

/**
 * Get the x509 module (lazy load)
 */
async function getX509() {
    if (x509Module) return x509Module;

    try {
        // Try npm package first (Node.js)
        x509Module = await import('@peculiar/x509');
    } catch {
        // Fall back to CDN for browser
        x509Module = await import('https://esm.sh/@peculiar/x509@1.9.7');
    }
    return x509Module;
}

/**
 * CT Lookup timeout in milliseconds
 */
const CT_LOOKUP_TIMEOUT = 5000;

/**
 * CT Lookup cache - stores results by certificate fingerprint
 * This dramatically speeds up batch validation where many transactions
 * use the same certificate.
 */
const ctLookupCache = new Map();

/**
 * Validate a certificate chain.
 *
 * @param {string[]} chainBase64 - Certificate chain as base64 DER strings (leaf first)
 * @param {Object} options - Validation options
 * @param {string} options.sni - Expected hostname (SNI) to validate against cert SANs
 * @param {boolean} options.verbose - Enable debug logging
 * @param {boolean} options.skipCtLookup - Skip CT lookup (for testing)
 * @param {number} options.evidenceTimestamp - Timestamp of evidence capture (microseconds)
 * @returns {Promise<{valid: boolean, level: string, error: string|null, details: Object}>}
 */
export async function validateCertificateChain(chainBase64, options = {}) {
    const { sni, verbose = false, skipCtLookup = false, evidenceTimestamp = null } = options;

    if (!chainBase64 || chainBase64.length === 0) {
        return { valid: false, level: 'none', error: 'Empty certificate chain', details: {} };
    }

    const details = {
        chainLength: chainBase64.length,
    };

    try {
        // 1. Parse leaf certificate to get fingerprint and metadata
        const leafCert = await parseCertificate(chainBase64[0]);
        if (!leafCert) {
            return { valid: false, level: 'none', error: 'Failed to parse leaf certificate', details };
        }

        details.subject = leafCert.subject;
        details.issuer = leafCert.issuer;
        details.notBefore = leafCert.notBefore;
        details.notAfter = leafCert.notAfter;

        // 2. Check certificate validity period
        const now = new Date();
        const evidenceDate = evidenceTimestamp ? new Date(evidenceTimestamp / 1000) : now;

        const certExpired = now > leafCert.notAfter;
        const certNotYetValid = now < leafCert.notBefore;
        const certWasValidAtCapture = evidenceDate >= leafCert.notBefore && evidenceDate <= leafCert.notAfter;

        if (certNotYetValid) {
            return {
                valid: false,
                level: 'none',
                error: 'Certificate not yet valid',
                details: { ...details, notBefore: leafCert.notBefore }
            };
        }

        if (certExpired) {
            if (certWasValidAtCapture) {
                details.certificateExpired = true;
                details.expiredAt = leafCert.notAfter;
                details.wasValidAtCapture = true;
                details.captureDate = evidenceDate;
            } else {
                return {
                    valid: false,
                    level: 'none',
                    error: 'Certificate was not valid at time of capture',
                    details: { ...details, expiredAt: leafCert.notAfter, captureDate: evidenceDate }
                };
            }
        }

        // 3. Verify SNI against certificate SANs
        if (sni) {
            const sniValid = await verifySniAgainstCert(sni, leafCert.sans || [], leafCert.commonName);
            details.sniVerified = sniValid;

            if (!sniValid) {
                return {
                    valid: false,
                    level: 'none',
                    error: `SNI '${sni}' not found in certificate SANs`,
                    details
                };
            }

            if (verbose) {
                console.log(`  [CHAIN] SNI '${sni}' verified against certificate`);
            }
        }

        // 4. Verify chain signatures (each cert signed by next)
        const sigResult = await verifyChainSignatures(chainBase64, verbose);
        details.chainSignaturesValid = sigResult.valid;

        if (!sigResult.valid) {
            return {
                valid: false,
                level: 'none',
                error: `Chain signature invalid: ${sigResult.error}`,
                details
            };
        }

        if (verbose) {
            console.log(`  [CHAIN] Chain signatures verified (${chainBase64.length} certs)`);
        }

        // 5. Check Certificate Transparency logs
        if (!skipCtLookup) {
            const fingerprint = await computeCertFingerprint(chainBase64[0]);
            details.fingerprint = fingerprint;

            const ctResult = await checkCertificateTransparency(fingerprint, verbose);
            details.ctLookup = ctResult;

            if (!ctResult.found) {
                // CT lookup failed or cert not found
                if (ctResult.error) {
                    // Network error - fall back to Mozilla root verification
                    details.ctWarning = ctResult.error;
                    if (verbose) {
                        console.log(`  [CHAIN] CT lookup failed: ${ctResult.error}, falling back to Mozilla roots`);
                    }

                    // Verify chain terminates at a trusted Mozilla root
                    const rootResult = await verifyChainAgainstMozillaRoots(chainBase64, verbose);
                    details.mozillaRootVerification = rootResult;

                    if (!rootResult.valid) {
                        return {
                            valid: false,
                            level: 'none',
                            error: `CT lookup failed and chain not trusted by Mozilla roots: ${rootResult.error}`,
                            details
                        };
                    }

                    if (verbose) {
                        console.log(`  [CHAIN] Chain verified against Mozilla root: ${rootResult.rootSubject}`);
                    }
                } else {
                    // Certificate genuinely not in CT logs - likely self-signed or fake CA
                    // Try Mozilla roots as last resort
                    if (verbose) {
                        console.log(`  [CHAIN] Certificate not in CT logs, checking Mozilla roots`);
                    }

                    const rootResult = await verifyChainAgainstMozillaRoots(chainBase64, verbose);
                    details.mozillaRootVerification = rootResult;

                    if (!rootResult.valid) {
                        return {
                            valid: false,
                            level: 'none',
                            error: 'Certificate not found in CT logs and not trusted by Mozilla roots (not issued by a public CA)',
                            details
                        };
                    }

                    if (verbose) {
                        console.log(`  [CHAIN] Chain verified against Mozilla root: ${rootResult.rootSubject}`);
                    }
                }
            } else {
                details.ctIssuer = ctResult.issuer;
                details.ctLoggedAt = ctResult.logged_at;

                if (verbose) {
                    console.log(`  [CHAIN] Certificate found in CT logs, issued by: ${ctResult.issuer}`);
                }
            }
        }

        // All checks passed
        const level = details.certificateExpired ? 'partial' : 'full';
        return { valid: true, level, error: null, details };

    } catch (e) {
        return {
            valid: false,
            level: 'none',
            error: `Chain validation error: ${e.message}`,
            details
        };
    }
}

/**
 * Parse a DER-encoded certificate to extract key fields.
 * Uses @peculiar/x509 which works in both Node.js and browser via WebCrypto.
 *
 * @param {string} certBase64 - Base64-encoded DER certificate
 * @returns {Promise<Object|null>}
 */
async function parseCertificate(certBase64) {
    try {
        const x509 = await getX509();
        const certDer = base64ToBytes(certBase64);
        const cert = new x509.X509Certificate(certDer);

        // Extract SANs from Subject Alternative Name extension
        const sans = [];
        const sanExt = cert.getExtension('2.5.29.17'); // OID for SAN
        if (sanExt && sanExt.names && sanExt.names.items) {
            // @peculiar/x509 getExtension() returns SubjectAlternativeNameExtension directly
            // names.items contains GeneralName objects with {type, value}
            for (const name of sanExt.names.items) {
                if (name.type === 'dns') {
                    sans.push(name.value);
                }
            }
        }

        // Extract Common Name from subject
        let commonName = null;
        const cnAttr = cert.subjectName.getField('2.5.4.3'); // OID for Common Name
        if (cnAttr && cnAttr.length > 0) {
            commonName = cnAttr[0];
        }

        // Compute SHA-256 fingerprint
        const fingerprint = await computeCertFingerprint(certBase64);

        return {
            subject: cert.subject,
            issuer: cert.issuer,
            notBefore: cert.notBefore,
            notAfter: cert.notAfter,
            sans,
            commonName,
            fingerprint,
            publicKey: cert.publicKey,
            raw: certDer,
            _cert: cert,  // Store the parsed cert for chain verification
        };
    } catch (e) {
        console.warn(`Certificate parsing error: ${e.message}`);
        return null;
    }
}

/**
 * Compute SHA-256 fingerprint of a certificate.
 *
 * @param {string} certBase64 - Base64-encoded DER certificate
 * @returns {Promise<string>} Hex-encoded fingerprint
 */
async function computeCertFingerprint(certBase64) {
    const certDer = base64ToBytes(certBase64);
    const hashBuffer = await crypto.subtle.digest('SHA-256', certDer);
    const hashArray = new Uint8Array(hashBuffer);
    return Array.from(hashArray).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Verify that SNI matches one of the certificate's SANs or Common Name.
 *
 * @param {string} sni - Hostname to verify
 * @param {string[]} sans - Subject Alternative Names from certificate
 * @param {string} commonName - Common Name from certificate subject
 * @returns {boolean}
 */
function verifySniAgainstCert(sni, sans, commonName) {
    // Check SANs first (preferred)
    for (const san of sans) {
        if (san === sni) {
            return true;
        }
        // Wildcard matching
        if (san.startsWith('*.')) {
            const wildcardDomain = san.slice(2);
            const sniParts = sni.split('.');
            if (sniParts.length >= 2) {
                const sniDomain = sniParts.slice(1).join('.');
                if (sniDomain === wildcardDomain) {
                    return true;
                }
            }
        }
    }

    // Fallback to Common Name (deprecated but still used)
    if (commonName && commonName === sni) {
        return true;
    }

    return false;
}

/**
 * Verify each certificate in chain is signed by the next one.
 * Uses @peculiar/x509 for browser-compatible verification.
 *
 * @param {string[]} chainBase64 - Certificate chain (leaf first)
 * @param {boolean} verbose - Enable debug logging
 * @returns {Promise<{valid: boolean, error: string|null}>}
 */
async function verifyChainSignatures(chainBase64, verbose) {
    try {
        const x509 = await getX509();

        for (let i = 0; i < chainBase64.length - 1; i++) {
            const certDer = base64ToBytes(chainBase64[i]);
            const issuerDer = base64ToBytes(chainBase64[i + 1]);

            const cert = new x509.X509Certificate(certDer);
            const issuer = new x509.X509Certificate(issuerDer);

            // Verify the certificate was signed by the issuer
            // Use signatureOnly: true to skip validity period check (we check that separately)
            // This allows validating expired certs that were valid at evidence capture time
            const valid = await cert.verify({
                publicKey: issuer.publicKey,
                signatureOnly: true,
            });

            if (!valid) {
                return {
                    valid: false,
                    error: `cert[${i}] not signed by cert[${i + 1}]`
                };
            }

            if (verbose) {
                console.log(`  [CHAIN] cert[${i}] signed by cert[${i + 1}]: OK`);
            }
        }

        // Verify root is self-signed (optional - root might not be in chain)
        if (chainBase64.length > 1) {
            const rootDer = base64ToBytes(chainBase64[chainBase64.length - 1]);
            const root = new x509.X509Certificate(rootDer);

            try {
                const selfSigned = await root.verify({
                    publicKey: root.publicKey,
                    signatureOnly: true,
                });
                if (verbose) {
                    console.log(`  [CHAIN] Root self-signed: ${selfSigned ? 'YES' : 'NO'}`);
                }
            } catch {
                // Root might not be self-signed if it's an intermediate
                if (verbose) {
                    console.log(`  [CHAIN] Root not self-signed (may be intermediate)`);
                }
            }
        }

        return { valid: true, error: null };
    } catch (e) {
        return { valid: false, error: e.message };
    }
}

/**
 * Query Certificate Transparency logs for a certificate.
 * Uses crt.sh as the CT log aggregator.
 *
 * @param {string} fingerprintHex - SHA-256 fingerprint of certificate
 * @param {boolean} verbose - Enable debug logging
 * @returns {Promise<{found: boolean, issuer: string|null, logged_at: string|null, error: string|null}>}
 */
async function checkCertificateTransparency(fingerprintHex, verbose) {
    // Check cache first
    if (ctLookupCache.has(fingerprintHex)) {
        const cached = ctLookupCache.get(fingerprintHex);
        if (verbose) {
            console.log(`  [CT] Cache hit for ${fingerprintHex.slice(0, 16)}...`);
        }
        return cached;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), CT_LOOKUP_TIMEOUT);

    try {
        // crt.sh accepts SHA-256 fingerprint queries
        const url = `https://crt.sh/?q=${fingerprintHex}&output=json`;

        if (verbose) {
            console.log(`  [CT] Looking up fingerprint: ${fingerprintHex.slice(0, 16)}...`);
        }

        const response = await fetch(url, {
            headers: { 'Accept': 'application/json' },
            signal: controller.signal,
        });

        if (!response.ok) {
            if (response.status === 404) {
                const result = { found: false, issuer: null, logged_at: null, error: null };
                ctLookupCache.set(fingerprintHex, result);
                return result;
            }
            throw new Error(`CT lookup failed: ${response.status}`);
        }

        const contentType = response.headers.get('content-type') || '';
        const text = await response.text();

        // Check if response is actually JSON
        if (!contentType.includes('json') && !text.trim().startsWith('[')) {
            // crt.sh returned an error page or rate limit response
            throw new Error('CT service returned non-JSON response (possibly rate limited)');
        }

        // crt.sh returns empty array or empty response for not found
        if (!text || text.trim() === '' || text.trim() === '[]') {
            const result = { found: false, issuer: null, logged_at: null, error: null };
            ctLookupCache.set(fingerprintHex, result);
            return result;
        }

        const results = JSON.parse(text);

        if (!results || results.length === 0) {
            const result = { found: false, issuer: null, logged_at: null, error: null };
            ctLookupCache.set(fingerprintHex, result);
            return result;
        }

        // Certificate found in CT logs - a real CA issued it
        const result = {
            found: true,
            issuer: results[0].issuer_name,
            logged_at: results[0].entry_timestamp,
            serial: results[0].serial_number,
            error: null
        };
        ctLookupCache.set(fingerprintHex, result);
        return result;

    } catch (e) {
        // Don't cache errors - they might be transient
        if (e.name === 'AbortError') {
            return { found: false, issuer: null, logged_at: null, error: 'CT lookup timed out' };
        }
        return { found: false, issuer: null, logged_at: null, error: `CT lookup error: ${e.message}` };
    } finally {
        clearTimeout(timeout);
    }
}

/**
 * Quick validation for testing - skips CT lookup.
 *
 * @param {string[]} chainBase64 - Certificate chain as base64 DER strings
 * @param {string} sni - Expected hostname
 * @returns {Promise<{valid: boolean, error: string|null}>}
 */
export async function validateChainQuick(chainBase64, sni) {
    return validateCertificateChain(chainBase64, { sni, skipCtLookup: true });
}

/**
 * Mozilla roots cache (parsed DER + X509Certificate objects)
 */
let mozillaRootsCache = null;

/**
 * Verify that a certificate chain terminates at a trusted Mozilla root.
 * Uses @peculiar/x509 for browser-compatible verification.
 *
 * Cross-signed chains may include certs beyond the trusted root for compatibility.
 * We check each certificate in the chain to see if:
 * 1. It IS a Mozilla root (by fingerprint match), OR
 * 2. It is SIGNED BY a Mozilla root
 *
 * This handles cases like Google's GTS Root R1 which is both a self-signed root
 * AND cross-signed by GlobalSign for older browser compatibility.
 *
 * @param {string[]} chainBase64 - Certificate chain (leaf first)
 * @param {boolean} verbose - Enable debug logging
 * @returns {Promise<{valid: boolean, rootSubject: string|null, error: string|null}>}
 */
async function verifyChainAgainstMozillaRoots(chainBase64, verbose) {
    try {
        const x509 = await getX509();

        // Fetch and cache Mozilla roots
        if (!mozillaRootsCache) {
            if (verbose) {
                console.log(`  [ROOTS] Fetching Mozilla root certificates...`);
            }

            const rootPems = await fetchMozillaRoots();
            if (!rootPems || rootPems.length === 0) {
                return { valid: false, rootSubject: null, error: 'Failed to fetch Mozilla roots' };
            }

            // Parse all roots into X509Certificate objects
            mozillaRootsCache = [];
            for (const pem of rootPems) {
                try {
                    const derBase64 = pemToDer(pem);
                    const derBuffer = base64ToBytes(derBase64);
                    const cert = new x509.X509Certificate(derBuffer);
                    const fingerprint = await computeCertFingerprint(derBase64);
                    mozillaRootsCache.push({
                        cert,
                        subject: cert.subject,
                        fingerprint,
                    });
                } catch {
                    // Skip malformed certs
                }
            }

            if (verbose) {
                console.log(`  [ROOTS] Loaded ${mozillaRootsCache.length} Mozilla root certificates`);
            }
        }

        // Check ALL certificates in the chain (not just the last one)
        // This handles cross-signed chains where a trusted root appears in the middle
        for (let i = 0; i < chainBase64.length; i++) {
            const certDer = base64ToBytes(chainBase64[i]);
            const cert = new x509.X509Certificate(certDer);
            const certFingerprint = await computeCertFingerprint(chainBase64[i]);

            // Check if this cert IS a Mozilla root
            for (const root of mozillaRootsCache) {
                if (root.fingerprint === certFingerprint) {
                    if (verbose) {
                        console.log(`  [ROOTS] Chain cert[${i}] is Mozilla root: ${root.subject}`);
                    }
                    return { valid: true, rootSubject: root.subject, error: null };
                }
            }

            // For non-leaf certs, also check if SIGNED BY a Mozilla root
            if (i > 0) {
                for (const root of mozillaRootsCache) {
                    try {
                        const valid = await cert.verify({
                            publicKey: root.cert.publicKey,
                            signatureOnly: true,
                        });
                        if (valid) {
                            if (verbose) {
                                console.log(`  [ROOTS] Chain cert[${i}] signed by Mozilla root: ${root.subject}`);
                            }
                            return { valid: true, rootSubject: root.subject, error: null };
                        }
                    } catch {
                        // This root doesn't sign the cert, try next
                    }
                }
            }
        }

        // Get last cert for error message
        const lastCertDer = base64ToBytes(chainBase64[chainBase64.length - 1]);
        const lastCert = new x509.X509Certificate(lastCertDer);

        // Not trusted by any Mozilla root
        return {
            valid: false,
            rootSubject: null,
            error: `No certificate in chain is trusted by Mozilla (last cert issuer: ${lastCert.issuer})`
        };

    } catch (e) {
        return { valid: false, rootSubject: null, error: `Mozilla root verification error: ${e.message}` };
    }
}
