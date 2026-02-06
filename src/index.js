/**
 * Harbour Forensic Validator
 * Public API for validating HTTP and WebSocket transactions using forensic evidence
 *
 * @module @harbour/validator
 */

// ============================================================================
// Validators
// ============================================================================

export { BaseValidator } from './validation/base-validator.js';
export { ValidationResult } from './validation/result.js';
export { Http1Validator } from './validation/http1.js';
export { Http2Validator } from './validation/http2.js';
export { Http3Validator } from './validation/http3.js';
export { WebSocketValidator } from './validation/websocket.js';

// ============================================================================
// Reconstructors
// ============================================================================

export { Http1Reconstructor } from './reconstruction/http1.js';
export { Http2Reconstructor } from './reconstruction/http2.js';
export { Http3Reconstructor } from './reconstruction/http3.js';
export { WebSocketReconstructor } from './reconstruction/websocket.js';

// ============================================================================
// Comparison & Hashing
// ============================================================================

export { TransactionHasher, hashTransaction, stableStringify } from './comparison/hasher.js';
export { TransactionComparator, findDifferences } from './comparison/comparator.js';
export { normalizeForValidation } from './comparison/normalizer.js';

// ============================================================================
// Crypto & Decryption
// ============================================================================

export { parseKeylog } from './crypto/keylog-parser.js';
export { decryptTlsRecords, extractServerRandom } from './crypto/decrypt-records.js';
export { extractFromTlsHandshake, extractWithFallback } from './certificate/tls-extractor.js';
export { extractFromQuicHandshake } from './certificate/quic-extractor.js';
export { validateCertificateChain } from './certificate/chain-validator.js';
export {
    extractHandshakeMetadata,
    computeTranscriptHash,
    verifyCertificateVerifySignature,
    verifyServerKeyExchangeSignature
} from './certificate/handshake-metadata-extractor.js';

// ============================================================================
// Protocol Parsers
// ============================================================================

export { parseRequest as parseHttp1Request, parseResponse as parseHttp1Response } from './protocol/http1/parser.js';
export { HpackDecoder } from './protocol/http2/hpack-decoder.js';
export { QpackDecoder } from './protocol/http3/qpack-decoder.js';
export { parseFrames as parseHttp2Frames, FrameType as Http2FrameType } from './protocol/http2/frame-parser.js';
export { parseFrames as parseHttp3Frames, FrameType as Http3FrameType } from './protocol/http3/frame-parser.js';
export { parseFrames as parseWebSocketFrames, OPCODE as WebSocketOpcode } from './protocol/websocket/frame-parser.js';

// ============================================================================
// Encoding Utilities
// ============================================================================

export { decodeVarint, varintLength } from './encoding/varint.js';
export { decodeHuffman } from './encoding/huffman.js';
export { decodeInteger } from './encoding/integer.js';
export { toBytes, base64ToBytes } from './encoding/bytes.js';

// ============================================================================
// Utilities
// ============================================================================

export { concatenate, concatenatePayloads, findDifferences as findObjectDifferences } from './utils/helpers.js';
export { buildNormalizedTransaction, normalizeHeaders } from './reconstruction/shared.js';

// ============================================================================
// Factory Functions
// ============================================================================

// Import validators for factory function
import { Http1Validator } from './validation/http1.js';
import { Http2Validator } from './validation/http2.js';
import { Http3Validator } from './validation/http3.js';
import { WebSocketValidator } from './validation/websocket.js';

/**
 * Create a validator for the specified protocol
 * @param {string} protocol - Protocol name ('HTTP/1.0', 'HTTP/1.1', 'HTTP/2', 'HTTP/3', 'WebSocket')
 * @param {Object} options - Validator options
 * @returns {BaseValidator} Protocol-specific validator
 * @throws {Error} If protocol is unknown
 */
export function createValidator(protocol, options = {}) {
    switch (protocol) {
        case 'HTTP/1.0':
        case 'HTTP/1.1':
            return new Http1Validator(options);
        case 'HTTP/2':
            return new Http2Validator(options);
        case 'HTTP/3':
            return new Http3Validator(options);
        case 'WebSocket':
            return new WebSocketValidator(options);
        default:
            throw new Error(`Unknown protocol: ${protocol}`);
    }
}

/**
 * Create a reconstructor for the specified protocol
 * @param {string} protocol - Protocol name
 * @param {Object} options - Reconstructor options
 * @returns {Object} Protocol-specific reconstructor
 * @throws {Error} If protocol is unknown
 */
export function createReconstructor(protocol, options = {}) {
    switch (protocol) {
        case 'HTTP/1.0':
        case 'HTTP/1.1':
            return new Http1Reconstructor(options);
        case 'HTTP/2':
            return new Http2Reconstructor(options);
        case 'HTTP/3':
            return new Http3Reconstructor(options);
        case 'WebSocket':
            return new WebSocketReconstructor(options);
        default:
            throw new Error(`Unknown protocol: ${protocol}`);
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * Validate a transaction using forensic evidence
 * Auto-detects protocol and uses appropriate validator
 *
 * BOUNDARY: This function separates claimed data from forensic evidence.
 * - Forensic evidence (self-contained cryptographic proof) goes to the validator for crypto work.
 * - Claimed data (what was captured) goes to the validator ONLY for the final hash comparison.
 *
 * Supports two formats:
 * 1. Wrapped: { type: 'transaction' | 'web_socket_message', data: {...} }
 * 2. Direct: { protocol: 'HTTP/2', ... } or WebSocket message object
 *
 * @param {Object} txWrapper - Transaction wrapper or direct transaction object
 * @param {Object} options - Validation options (verbose, skipCtLookup, etc.)
 * @returns {Promise<ValidationResult>} Validation result
 *
 * @example
 * import { validate } from '@harbour/validator';
 *
 * // Wrapped format (from JSONL file)
 * const result = await validate(wrapper, { verbose: true });
 *
 * // Direct format
 * const result = await validate(tx, { verbose: true });
 *
 * if (result.valid && result.level === 'full') {
 *   console.log('Transaction fully validated!');
 * }
 */
export async function validate(txWrapper, options = {}) {
    // Handle wrapped format
    const record = txWrapper.data || txWrapper;
    const type = txWrapper.type || (record.message_type ? 'web_socket_message' : 'transaction');

    // Extract forensic evidence (self-contained cryptographic proof)
    const evidence = record.forensic_evidence;
    if (!evidence) {
        return { valid: false, level: 'none', error: 'No forensic evidence', details: {} };
    }

    // Extract claimed data separately — this is what we're validating AGAINST.
    // It NEVER enters the cryptographic validation workflow.
    // Backward compat: if claimed_tls doesn't exist, fall back to evidence.certificate_info (old format).
    const claimed = {
        id: record.id,
        protocol: record.protocol,
        request: record.request,
        response: record.response,
        connection: record.connection,
        tls: record.claimed_tls || evidence.certificate_info || null,
        // For WebSocket messages
        message_type: record.message_type,
        direction: record.direction,
        text: record.text,
        payload: record.payload,
        close_code: record.close_code,
        close_reason: record.close_reason,
        timestamp_us: record.timestamp_us,
        url: record.url,
        // Preserve compressed_payload for WebSocket compression support
        compressed_payload: record.compressed_payload,
    };

    // Route to protocol-specific validator
    // Validators receive (evidence, claimed) — evidence for crypto, claimed for comparison
    if (type === 'web_socket_message') {
        return new WebSocketValidator(options).validate(evidence, claimed);
    }

    switch (record.protocol) {
        case 'HTTP/2':
            return new Http2Validator(options).validate(evidence, claimed);
        case 'HTTP/3':
            return new Http3Validator(options).validate(evidence, claimed);
        case 'HTTP/1.1':
        case 'HTTP/1.0':
            return new Http1Validator(options).validate(evidence, claimed);
        default:
            return { valid: false, level: 'none', error: `Unknown protocol: ${record.protocol}`, details: {} };
    }
}

/**
 * Reconstruct a transaction from forensic evidence
 * Auto-detects protocol and uses appropriate reconstructor
 *
 * @param {Object} transaction - Transaction object (for protocol detection)
 * @param {Object} evidence - Forensic evidence
 * @param {Object} options - Reconstruction options
 * @returns {Promise<{reconstructed: Object|null, error: string|null}>} Reconstruction result
 *
 * @example
 * import { reconstruct } from '@harbour/validator';
 *
 * const { reconstructed, error } = await reconstruct(transaction, evidence);
 * if (reconstructed) {
 *   console.log('Reconstructed:', reconstructed);
 * }
 */
export async function reconstruct(transaction, evidence, options = {}) {
    const reconstructor = createReconstructor(transaction.protocol, options);
    return await reconstructor.reconstruct(transaction, evidence);
}

/**
 * Compare two transactions and return detailed differences
 *
 * @param {Object} original - Original transaction
 * @param {Object} reconstructed - Reconstructed transaction
 * @returns {Promise<{match: boolean, differences: Array<string>}>} Comparison result
 *
 * @example
 * import { compare } from '@harbour/validator';
 *
 * const { match, differences } = await compare(original, reconstructed);
 * if (!match) {
 *   console.log('Differences found:', differences);
 * }
 */
export async function compare(original, reconstructed) {
    const comparator = new TransactionComparator();
    return await comparator.compare(original, reconstructed);
}
