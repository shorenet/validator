/**
 * Base certificate extraction logic shared by TLS and QUIC.
 * Handles parsing of TLS Certificate messages in various formats.
 *
 * Browser/Node.js compatible:
 * - Uses pako for zlib decompression
 * - Uses brotli-wasm for Brotli decompression (works in both environments)
 */

import { parseCertificateChain } from './parser.js';
import pako from 'pako';

// Brotli decompression - loaded differently for Node.js vs browser
let brotliDecompress = null;

// In Node.js, load brotli-wasm synchronously using require
if (typeof process !== 'undefined' && process.versions?.node) {
    try {
        const { createRequire } = await import('node:module');
        const require = createRequire(import.meta.url);
        const brotli = require('brotli-wasm');
        brotliDecompress = brotli.decompress;
    } catch (e) {
        // brotli-wasm not available in Node.js
        console.warn('[CERT] brotli-wasm not available:', e.message);
    }
} else {
    // In browser, dynamically import from local lib (uses import map)
    try {
        const brotli = await import('brotli-wasm');
        console.log('[CERT] brotli-wasm module loaded:', Object.keys(brotli));

        // Local brotli-wasm exports: default (init function) + decompress (named export)
        // Must call init() first to load WASM, then decompress becomes usable
        if (typeof brotli.default === 'function') {
            console.log('[CERT] Initializing brotli WASM...');
            await brotli.default();
            console.log('[CERT] WASM initialized');
        }

        // After init, decompress should be available as named export
        if (typeof brotli.decompress === 'function') {
            brotliDecompress = brotli.decompress;
            console.log('[CERT] brotli-wasm: decompress function ready');
        } else {
            console.warn('[CERT] brotli-wasm: decompress not found after init');
        }
    } catch (e) {
        // brotli-wasm not available in browser
        console.warn('[CERT] brotli-wasm not available:', e.message);
    }
}

/**
 * TLS handshake message types
 */
export const TLS_HANDSHAKE_TYPE = {
    CLIENT_HELLO: 1,
    SERVER_HELLO: 2,
    NEW_SESSION_TICKET: 4,
    ENCRYPTED_EXTENSIONS: 8,
    CERTIFICATE: 11,
    SERVER_KEY_EXCHANGE: 12,
    CERTIFICATE_REQUEST: 13,
    SERVER_HELLO_DONE: 14,
    CERTIFICATE_VERIFY: 15,
    FINISHED: 20,
    COMPRESSED_CERTIFICATE: 25
};

/**
 * Convert bytes to base64 string.
 *
 * @param {Uint8Array} bytes - Bytes to convert
 * @returns {string} Base64-encoded string
 */
export function bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/**
 * Find and parse Certificate message in TLS handshake data.
 * Handles both TLS 1.2 (plaintext) and TLS 1.3 (with extensions) formats.
 * Also handles CompressedCertificate messages (RFC 8879).
 *
 * @param {Uint8Array} data - Handshake message data
 * @param {boolean} verbose - Enable debug logging
 * @param {boolean} isTls13 - True for TLS 1.3 format (with per-cert extensions)
 * @returns {string[]|null} Certificate chain as base64 DER strings, or null if not found
 */
export function findCertificateInHandshakeData(data, verbose = false, isTls13 = true) {
    let offset = 0;

    const typeNames = {
        1: 'ClientHello', 2: 'ServerHello', 4: 'NewSessionTicket',
        8: 'EncryptedExtensions', 11: 'Certificate', 12: 'ServerKeyExchange',
        13: 'CertificateRequest', 14: 'ServerHelloDone', 15: 'CertificateVerify',
        20: 'Finished', 25: 'CompressedCertificate'
    };

    while (offset + 4 <= data.length) {
        const hsType = data[offset];
        const hsLen = (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];

        if (hsLen === 0 || offset + 4 + hsLen > data.length) {
            if (verbose) {
                console.log(`  [CERT] Breaking at offset ${offset}: hsLen=${hsLen}, remaining=${data.length - offset}`);
            }
            break;
        }

        if (verbose) {
            console.log(`  [CERT] TLS message: type=${hsType} (${typeNames[hsType] || 'Unknown'}), len=${hsLen}, offset=${offset}`);
        }

        // Certificate message (type 11)
        if (hsType === TLS_HANDSHAKE_TYPE.CERTIFICATE) {
            const certData = data.slice(offset + 4, offset + 4 + hsLen);

            if (verbose) {
                console.log(`  [CERT] Found Certificate message, length=${certData.length}`);
            }

            try {
                const chain = isTls13
                    ? parseTls13CertificateChain(certData, verbose)
                    : parseTls12CertificateChain(certData, verbose);

                if (chain && chain.length > 0) {
                    return chain;
                }
            } catch (e) {
                if (verbose) {
                    console.log(`  [CERT] Failed to parse certificate chain: ${e.message}`);
                }
            }
        }

        // CompressedCertificate message (type 25) - RFC 8879, TLS 1.3 only
        if (hsType === TLS_HANDSHAKE_TYPE.COMPRESSED_CERTIFICATE && isTls13) {
            const ccData = data.slice(offset + 4, offset + 4 + hsLen);

            if (verbose) {
                console.log(`  [CERT] Found CompressedCertificate message, length=${ccData.length}`);
            }

            try {
                const chain = decompressAndParseCertificate(ccData, verbose);
                if (chain && chain.length > 0) {
                    return chain;
                }
            } catch (e) {
                if (verbose) {
                    console.log(`  [CERT] Failed to decompress certificate: ${e.message}`);
                }
            }
        }

        offset += 4 + hsLen;
    }

    return null;
}

/**
 * Parse TLS 1.3 certificate chain format.
 * TLS 1.3 has extensions after each certificate entry.
 *
 * Format:
 * - request_context_length (1 byte)
 * - request_context (variable)
 * - certificate_list_length (3 bytes)
 * - For each certificate:
 *   - cert_data_length (3 bytes)
 *   - cert_data (variable)
 *   - extensions_length (2 bytes)
 *   - extensions (variable)
 *
 * @param {Uint8Array} data - Certificate message body
 * @param {boolean} verbose - Enable debug logging
 * @returns {string[]|null} Certificate chain as base64 DER strings
 */
export function parseTls13CertificateChain(data, verbose = false) {
    const chain = [];
    let offset = 0;

    // request_context_length (1 byte) - usually 0 for server certs
    if (offset >= data.length) return null;
    const contextLen = data[offset];
    offset += 1 + contextLen;

    if (offset + 3 > data.length) return null;

    // certificate_list_length (3 bytes)
    const listLen = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];
    offset += 3;

    const listEnd = offset + listLen;

    while (offset + 3 <= listEnd && offset + 3 <= data.length) {
        // cert_data_length (3 bytes)
        const certLen = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];
        offset += 3;

        if (offset + certLen > data.length) break;

        // cert_data
        const certData = data.slice(offset, offset + certLen);
        chain.push(bytesToBase64(certData));
        offset += certLen;

        if (offset + 2 > data.length) break;

        // extensions_length (2 bytes) - TLS 1.3 specific
        const extLen = (data[offset] << 8) | data[offset + 1];
        offset += 2 + extLen;
    }

    if (verbose) {
        console.log(`  [CERT] Parsed ${chain.length} TLS 1.3 certificates`);
    }

    return chain.length > 0 ? chain : null;
}

/**
 * Parse TLS 1.2 certificate chain format.
 * Uses the existing certificate parser from certificate.js.
 *
 * @param {Uint8Array} data - Certificate message body
 * @param {boolean} verbose - Enable debug logging
 * @returns {string[]|null} Certificate chain as base64 DER strings
 */
export function parseTls12CertificateChain(data, verbose = false) {
    const certs = parseCertificateChain(data);

    if (certs.length > 0) {
        const chain = certs.map(cert => {
            if (cert.raw) {
                return bytesToBase64(cert.raw);
            }
            return null;
        }).filter(c => c !== null);

        if (verbose) {
            console.log(`  [CERT] Parsed ${chain.length} TLS 1.2 certificates`);
        }

        return chain.length > 0 ? chain : null;
    }

    return null;
}

/**
 * Decompress and parse a CompressedCertificate message (RFC 8879).
 *
 * Format:
 * - algorithm (2 bytes): 1=zlib, 2=brotli, 3=zstd
 * - uncompressed_length (3 bytes)
 * - compressed_certificate_message length (3 bytes)
 * - compressed_certificate_message (variable)
 *
 * @param {Uint8Array} ccData - CompressedCertificate message body
 * @param {boolean} verbose - Enable debug logging
 * @returns {string[]|null} Certificate chain as base64 DER strings
 */
export function decompressAndParseCertificate(ccData, verbose = false) {
    if (ccData.length < 8) {
        throw new Error('CompressedCertificate too short');
    }

    const algorithm = (ccData[0] << 8) | ccData[1];
    const uncompLen = (ccData[2] << 16) | (ccData[3] << 8) | ccData[4];
    const compLen = (ccData[5] << 16) | (ccData[6] << 8) | ccData[7];
    const compData = ccData.slice(8, 8 + compLen);

    if (verbose) {
        const algNames = { 1: 'zlib', 2: 'brotli', 3: 'zstd' };
        console.log(`  [CERT] Compression: ${algNames[algorithm] || algorithm}, uncompressed=${uncompLen}, compressed=${compLen}`);
    }

    let decompressed;
    if (algorithm === 2) {
        // Brotli decompression using brotli-wasm
        if (!brotliDecompress) {
            throw new Error('Brotli-compressed certificates not supported (brotli-wasm not loaded)');
        }
        try {
            decompressed = new Uint8Array(brotliDecompress(compData));
        } catch (e) {
            throw new Error(`Brotli decompression failed: ${e.message}`);
        }
    } else if (algorithm === 1) {
        // zlib decompression using pako
        decompressed = pako.inflate(compData);
    } else {
        throw new Error(`Unsupported compression algorithm: ${algorithm}`);
    }

    if (verbose) {
        console.log(`  [CERT] Decompressed certificate: ${decompressed.length} bytes`);
    }

    // The decompressed data is a Certificate message body (without the handshake header)
    // Parse it as TLS 1.3 certificate chain
    return parseTls13CertificateChain(new Uint8Array(decompressed), verbose);
}
