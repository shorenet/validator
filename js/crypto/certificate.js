/**
 * X.509 Certificate Parser
 * Parses DER-encoded certificates for display in validation results.
 */

/**
 * ASN.1 tag types
 */
const ASN1_TAG = {
    BOOLEAN: 0x01,
    INTEGER: 0x02,
    BIT_STRING: 0x03,
    OCTET_STRING: 0x04,
    NULL: 0x05,
    OBJECT_IDENTIFIER: 0x06,
    UTF8_STRING: 0x0c,
    PRINTABLE_STRING: 0x13,
    IA5_STRING: 0x16,
    UTC_TIME: 0x17,
    GENERALIZED_TIME: 0x18,
    SEQUENCE: 0x30,
    SET: 0x31
};

/**
 * Common OID mappings
 */
const OIDS = {
    '2.5.4.3': 'CN', // Common Name
    '2.5.4.6': 'C',  // Country
    '2.5.4.7': 'L',  // Locality
    '2.5.4.8': 'ST', // State
    '2.5.4.10': 'O', // Organization
    '2.5.4.11': 'OU', // Organizational Unit
    '1.2.840.113549.1.1.1': 'RSA',
    '1.2.840.113549.1.1.5': 'SHA1withRSA',
    '1.2.840.113549.1.1.11': 'SHA256withRSA',
    '1.2.840.113549.1.1.12': 'SHA384withRSA',
    '1.2.840.113549.1.1.13': 'SHA512withRSA',
    '1.2.840.10045.2.1': 'EC',
    '1.2.840.10045.4.3.2': 'SHA256withECDSA',
    '1.2.840.10045.4.3.3': 'SHA384withECDSA',
    '1.2.840.10045.4.3.4': 'SHA512withECDSA',
    '1.3.6.1.5.5.7.1.1': 'authorityInfoAccess',
    '1.3.6.1.5.5.7.3.1': 'serverAuth',
    '1.3.6.1.5.5.7.3.2': 'clientAuth',
    '2.5.29.14': 'subjectKeyIdentifier',
    '2.5.29.15': 'keyUsage',
    '2.5.29.17': 'subjectAltName',
    '2.5.29.19': 'basicConstraints',
    '2.5.29.31': 'cRLDistributionPoints',
    '2.5.29.32': 'certificatePolicies',
    '2.5.29.35': 'authorityKeyIdentifier',
    '2.5.29.37': 'extKeyUsage'
};

/**
 * Parse ASN.1 length.
 * @param {Uint8Array} data
 * @param {number} offset
 * @returns {{length: number, bytesRead: number}}
 */
function parseLength(data, offset) {
    const first = data[offset];

    if (first < 0x80) {
        // Short form
        return { length: first, bytesRead: 1 };
    }

    // Long form
    const numBytes = first & 0x7f;
    let length = 0;

    for (let i = 0; i < numBytes; i++) {
        length = (length << 8) | data[offset + 1 + i];
    }

    return { length, bytesRead: 1 + numBytes };
}

/**
 * Parse ASN.1 TLV (Tag-Length-Value).
 * @param {Uint8Array} data
 * @param {number} offset
 * @returns {{tag: number, length: number, value: Uint8Array, totalBytes: number}}
 */
function parseTLV(data, offset) {
    const tag = data[offset];
    const { length, bytesRead } = parseLength(data, offset + 1);
    const valueStart = offset + 1 + bytesRead;
    const value = data.slice(valueStart, valueStart + length);

    return {
        tag,
        length,
        value,
        totalBytes: 1 + bytesRead + length
    };
}

/**
 * Parse an OID from bytes.
 * @param {Uint8Array} data
 * @returns {string}
 */
function parseOID(data) {
    const components = [];

    // First byte encodes first two components
    components.push(Math.floor(data[0] / 40));
    components.push(data[0] % 40);

    // Remaining bytes use base-128 encoding
    let value = 0;
    for (let i = 1; i < data.length; i++) {
        const byte = data[i];
        value = (value << 7) | (byte & 0x7f);

        if ((byte & 0x80) === 0) {
            components.push(value);
            value = 0;
        }
    }

    return components.join('.');
}

/**
 * Parse an ASN.1 string (various types).
 * @param {Uint8Array} data
 * @param {number} tag
 * @returns {string}
 */
function parseString(data, tag) {
    return new TextDecoder('utf-8', { fatal: false }).decode(data);
}

/**
 * Parse ASN.1 time.
 * @param {Uint8Array} data
 * @param {number} tag
 * @returns {Date}
 */
function parseTime(data, tag) {
    const str = new TextDecoder('ascii').decode(data);

    if (tag === ASN1_TAG.UTC_TIME) {
        // YYMMDDHHMMSSZ
        let year = parseInt(str.substring(0, 2), 10);
        year += year >= 50 ? 1900 : 2000;

        return new Date(Date.UTC(
            year,
            parseInt(str.substring(2, 4), 10) - 1,
            parseInt(str.substring(4, 6), 10),
            parseInt(str.substring(6, 8), 10),
            parseInt(str.substring(8, 10), 10),
            parseInt(str.substring(10, 12), 10)
        ));
    } else {
        // YYYYMMDDHHMMSSZ
        return new Date(Date.UTC(
            parseInt(str.substring(0, 4), 10),
            parseInt(str.substring(4, 6), 10) - 1,
            parseInt(str.substring(6, 8), 10),
            parseInt(str.substring(8, 10), 10),
            parseInt(str.substring(10, 12), 10),
            parseInt(str.substring(12, 14), 10)
        ));
    }
}

/**
 * Parse X.500 Name (issuer/subject).
 * @param {Uint8Array} data
 * @returns {Object}
 */
function parseName(data) {
    const result = {};
    let offset = 0;

    // SEQUENCE of SETs of SEQUENCE of (OID, value)
    const seq = parseTLV(data, offset);
    let innerOffset = 0;

    while (innerOffset < seq.value.length) {
        const set = parseTLV(seq.value, innerOffset);
        let setOffset = 0;

        while (setOffset < set.value.length) {
            const rdn = parseTLV(set.value, setOffset);
            let rdnOffset = 0;

            // Parse OID
            const oidTlv = parseTLV(rdn.value, rdnOffset);
            const oid = parseOID(oidTlv.value);
            rdnOffset += oidTlv.totalBytes;

            // Parse value
            const valueTlv = parseTLV(rdn.value, rdnOffset);
            const value = parseString(valueTlv.value, valueTlv.tag);

            const name = OIDS[oid] || oid;
            result[name] = value;

            setOffset += rdn.totalBytes;
        }

        innerOffset += set.totalBytes;
    }

    return result;
}

/**
 * Parse X.509 certificate validity period.
 * @param {Uint8Array} data
 * @returns {{notBefore: Date, notAfter: Date}}
 */
function parseValidity(data) {
    const seq = parseTLV(data, 0);
    let offset = 0;

    const notBeforeTlv = parseTLV(seq.value, offset);
    const notBefore = parseTime(notBeforeTlv.value, notBeforeTlv.tag);
    offset += notBeforeTlv.totalBytes;

    const notAfterTlv = parseTLV(seq.value, offset);
    const notAfter = parseTime(notAfterTlv.value, notAfterTlv.tag);

    return { notBefore, notAfter };
}

/**
 * Parse X.509 certificate from DER-encoded bytes.
 * @param {Uint8Array} data
 * @returns {Object}
 */
export function parseCertificate(data) {
    try {
        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
        const cert = parseTLV(data, 0);
        let offset = 0;

        // TBSCertificate
        const tbs = parseTLV(cert.value, offset);
        offset += tbs.totalBytes;

        // Parse TBSCertificate fields
        let tbsOffset = 0;

        // Version (optional, tagged [0])
        let version = 1;
        if ((tbs.value[tbsOffset] & 0xe0) === 0xa0) {
            const versionTlv = parseTLV(tbs.value, tbsOffset);
            const versionInner = parseTLV(versionTlv.value, 0);
            version = versionInner.value[0] + 1;
            tbsOffset += versionTlv.totalBytes;
        }

        // Serial number
        const serialTlv = parseTLV(tbs.value, tbsOffset);
        const serial = Array.from(serialTlv.value)
            .map(b => b.toString(16).padStart(2, '0'))
            .join(':');
        tbsOffset += serialTlv.totalBytes;

        // Signature algorithm
        const sigAlgTlv = parseTLV(tbs.value, tbsOffset);
        const sigAlgOidTlv = parseTLV(sigAlgTlv.value, 0);
        const signatureAlgorithm = OIDS[parseOID(sigAlgOidTlv.value)] || parseOID(sigAlgOidTlv.value);
        tbsOffset += sigAlgTlv.totalBytes;

        // Issuer
        const issuerTlv = parseTLV(tbs.value, tbsOffset);
        const issuer = parseName(issuerTlv.value);
        tbsOffset += issuerTlv.totalBytes;

        // Validity
        const validityTlv = parseTLV(tbs.value, tbsOffset);
        const validity = parseValidity(validityTlv.value);
        tbsOffset += validityTlv.totalBytes;

        // Subject
        const subjectTlv = parseTLV(tbs.value, tbsOffset);
        const subject = parseName(subjectTlv.value);
        tbsOffset += subjectTlv.totalBytes;

        // Subject Public Key Info
        const pubKeyTlv = parseTLV(tbs.value, tbsOffset);
        const pubKeyAlgTlv = parseTLV(pubKeyTlv.value, 0);
        const pubKeyAlgOidTlv = parseTLV(pubKeyAlgTlv.value, 0);
        const publicKeyAlgorithm = OIDS[parseOID(pubKeyAlgOidTlv.value)] || parseOID(pubKeyAlgOidTlv.value);

        return {
            version,
            serial,
            signatureAlgorithm,
            issuer,
            subject,
            notBefore: validity.notBefore,
            notAfter: validity.notAfter,
            publicKeyAlgorithm,
            raw: data
        };
    } catch (e) {
        return {
            error: `Failed to parse certificate: ${e.message}`,
            raw: data
        };
    }
}

/**
 * Format a distinguished name for display.
 * @param {Object} name
 * @returns {string}
 */
export function formatDN(name) {
    const parts = [];
    if (name.CN) parts.push(`CN=${name.CN}`);
    if (name.O) parts.push(`O=${name.O}`);
    if (name.OU) parts.push(`OU=${name.OU}`);
    if (name.L) parts.push(`L=${name.L}`);
    if (name.ST) parts.push(`ST=${name.ST}`);
    if (name.C) parts.push(`C=${name.C}`);
    return parts.join(', ') || 'Unknown';
}

/**
 * Check if a certificate is currently valid.
 * @param {Object} cert
 * @returns {boolean}
 */
export function isCertificateValid(cert) {
    if (!cert.notBefore || !cert.notAfter) return false;
    const now = new Date();
    return now >= cert.notBefore && now <= cert.notAfter;
}

/**
 * Parse a certificate chain from TLS handshake.
 * @param {Uint8Array} data - Certificate message data (after handshake header)
 * @returns {Array<Object>}
 */
export function parseCertificateChain(data) {
    const certs = [];
    let offset = 0;

    // First 3 bytes are total length
    const totalLength = (data[0] << 16) | (data[1] << 8) | data[2];
    offset = 3;

    while (offset < 3 + totalLength && offset + 3 <= data.length) {
        const certLength = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];
        offset += 3;

        if (offset + certLength > data.length) break;

        const certData = data.slice(offset, offset + certLength);
        certs.push(parseCertificate(certData));
        offset += certLength;
    }

    return certs;
}

/**
 * Parse PEM-encoded certificate.
 * @param {string} pem
 * @returns {Object}
 */
export function parsePEM(pem) {
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

    const binary = atob(base64);
    const data = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        data[i] = binary.charCodeAt(i);
    }

    return parseCertificate(data);
}
