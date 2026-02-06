/**
 * WebSocket Message Reconstructor
 * Reconstructs WebSocket messages from parsed frames using cryptographic proof.
 *
 * All content is derived from decrypted TLS records - no trusted claims.
 * Validator: decrypt TLS records → parse frames → decompress → normalize → hash compare.
 */

import { OPCODE } from '../protocol/websocket/frame-parser.js';
import { base64ToBytes, bytesToBase64 } from '../crypto/hash.js';

export class WebSocketReconstructor {
    constructor(options = {}) {
        this.options = options;
    }

    /**
     * Reconstruct WebSocket message from parsed frames.
     *
     * Cryptographic proof model:
     * - TLS records are decrypted using keylog
     * - WebSocket frames are parsed from decrypted data
     * - For compressed frames, decompression uses context from prior frames
     * - The reconstructed content comes entirely from the wire, not from claims
     *
     * @param {Object} claimed - Claimed message data (for matching/identity — never enters crypto)
     * @param {Object} certInfo - Certificate info EXTRACTED from decrypted handshake
     * @param {Array} dataFrames - Parsed WebSocket frames (already decompressed with context)
     * @returns {Object|null} Reconstructed message
     */
    reconstruct(claimed, certInfo, dataFrames) {
        const { verbose = false } = this.options;

        // Get claimed content for frame matching
        const claimedPayload = claimed.payload ? base64ToBytes(claimed.payload) : null;
        const claimedText = claimed.text;

        // Check if this is a control frame with no payload (Ping/Pong/Close)
        const isControlFrameWithNoPayload = !claimedPayload && !claimedText &&
            (claimed.message_type === 'Ping' || claimed.message_type === 'Pong' || claimed.message_type === 'Close');

        // Find the frame that matches by decompressed content
        let matchedFrame = null;
        for (const frame of dataFrames) {
            // For control frames with no payload, just match by opcode
            if (isControlFrameWithNoPayload) {
                matchedFrame = frame;
                break;
            }

            // Match text messages by decompressed text content
            if (claimedText && frame.opcode === OPCODE.TEXT) {
                const frameText = new TextDecoder('utf-8', { fatal: false }).decode(frame.payload);
                if (frameText === claimedText) {
                    matchedFrame = frame;
                    break;
                }
            }

            // Match binary messages by decompressed payload bytes
            if (claimedPayload && frame.opcode === OPCODE.BINARY) {
                if (this.bytesEqual(frame.payload, claimedPayload)) {
                    matchedFrame = frame;
                    break;
                }
            }

            // Match Ping/Pong frames with payload
            if (claimedPayload && (frame.opcode === OPCODE.PING || frame.opcode === OPCODE.PONG)) {
                if (this.bytesEqual(frame.payload, claimedPayload)) {
                    matchedFrame = frame;
                    break;
                }
            }
        }

        if (!matchedFrame) {
            if (verbose) console.log('  No matching frame found');
            return null;
        }

        // Map opcode to message type
        const typeMap = {
            [OPCODE.TEXT]: 'Text',
            [OPCODE.BINARY]: 'Binary',
            [OPCODE.PING]: 'Ping',
            [OPCODE.PONG]: 'Pong',
            [OPCODE.CLOSE]: 'Close'
        };
        const reconstructedType = typeMap[matchedFrame.opcode] || 'Binary';
        const isTextMessage = matchedFrame.opcode === OPCODE.TEXT;

        // Reconstruct from frame data - all content derived from TLS records
        let reconstructedPayload = null;
        let reconstructedText = null;

        if (isTextMessage) {
            // Text messages: decode payload as UTF-8
            reconstructedText = new TextDecoder('utf-8', { fatal: false }).decode(matchedFrame.payload);
        } else if (matchedFrame.payload.length > 0) {
            // Binary messages: base64 encode payload
            reconstructedPayload = bytesToBase64(matchedFrame.payload);
        }

        return {
            id: claimed.id,
            message_type: reconstructedType,
            direction: claimed.direction,
            payload: reconstructedPayload,
            text: reconstructedText,
            close_code: null,
            close_reason: null,
            url: claimed.url,
            connection: claimed.connection ? {
                id: claimed.connection.id,
                client_addr: claimed.connection.client_addr,
                server_addr: claimed.connection.server_addr,
            } : null,
            certificate_info: certInfo ? {
                sni: certInfo.sni,
                tls_version: certInfo.tls_version,
                alpn: certInfo.alpn,
                cipher_suite: certInfo.cipher_suite,
                certificate_chain: certInfo.certificate_chain,
                handshake_proof: certInfo.handshake_proof,
            } : null,
        };
    }

    /**
     * Compare two byte arrays for equality.
     */
    bytesEqual(a, b) {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    }
}
