/**
 * HTTP/2 Transaction Reconstructor
 * Reconstructs HTTP/2 transactions from decrypted frames
 */

import { HpackDecoder } from '../protocol/http2/hpack-decoder.js';
import { parseFrames, FrameType, extractHeaderBlock } from '../protocol/http2/frame-parser.js';
import { buildNormalizedTransaction } from './shared.js';

export class Http2Reconstructor {
    constructor(options = {}) {
        this.options = options;
    }

    /**
     * Reconstruct HTTP/2 transaction from decrypted plaintext
     * @param {Object} claimed - Claimed transaction data (for identity fields)
     * @param {Object} evidence - Forensic evidence (for stream_id, etc.)
     * @param {Array} allPlaintext - Decrypted plaintext segments
     * @returns {{reconstructed: Object|null, error: string|null}}
     */
    async reconstruct(claimed, evidence, allPlaintext) {
        const { verbose = false } = this.options;
        const streamId = evidence.stream_id;

        if (!streamId) {
            return { reconstructed: null, error: 'Missing stream_id' };
        }

        // Initialize fresh HPACK decoders - table builds up as we process ALL HEADERS frames.
        // HPACK state is deterministic: same sequence of HEADERS produces same table state.
        const requestHpack = new HpackDecoder();
        const responseHpack = new HpackDecoder();

        let parsedRequest = null;
        let parsedResponse = null;
        let foundRequestHeaders = false;
        let foundResponseHeaders = false;

        // Helper to strip HTTP/2 connection preface
        const stripPreface = (data) => {
            const preface = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';
            const prefaceBytes = new TextEncoder().encode(preface);
            if (data.length >= prefaceBytes.length) {
                let isPreface = true;
                for (let i = 0; i < prefaceBytes.length; i++) {
                    if (data[i] !== prefaceBytes[i]) { isPreface = false; break; }
                }
                if (isPreface) return data.slice(prefaceBytes.length);
            }
            return data;
        };

        // Collect all frames by direction
        const allFrames = { client: [], server: [] };
        for (const { direction, data } of allPlaintext) {
            const frameData = direction === 'client' ? stripPreface(data) : data;
            try {
                const frames = parseFrames(frameData);
                allFrames[direction].push(...frames);
            } catch (e) {
                if (verbose) console.log(`  Frame parse error: ${e.message}`);
            }
        }

        // Process ALL HEADERS frames to build table, extract target stream's headers
        // CRITICAL: Can't skip non-target streams because they update the shared HPACK table
        for (const frame of allFrames.client) {
            if (frame.type !== FrameType.HEADERS) continue;
            try {
                const headerBlock = extractHeaderBlock(frame.payload, frame.flags);
                const headers = requestHpack.decode(headerBlock);

                // Only extract for target stream
                if (frame.streamId === streamId && !foundRequestHeaders) {
                    foundRequestHeaders = true;
                    const headerMap = {};
                    for (const [name, value] of headers) {
                        headerMap[name] = value;
                    }
                    parsedRequest = {
                        method: headerMap[':method'],
                        path: headerMap[':path'],
                        authority: headerMap[':authority'],
                        scheme: headerMap[':scheme'],
                        headers: headerMap
                    };
                }
            } catch (e) {
                if (verbose) console.log(`  HPACK decode error on stream ${frame.streamId}: ${e.message}`);
            }
        }

        for (const frame of allFrames.server) {
            if (frame.type !== FrameType.HEADERS) continue;
            try {
                const headerBlock = extractHeaderBlock(frame.payload, frame.flags);
                const headers = responseHpack.decode(headerBlock);

                // Only extract for target stream
                if (frame.streamId === streamId && !foundResponseHeaders) {
                    foundResponseHeaders = true;
                    const headerMap = {};
                    for (const [name, value] of headers) {
                        headerMap[name] = value;
                    }
                    parsedResponse = {
                        status: parseInt(headerMap[':status'], 10),
                        headers: headerMap
                    };
                }
            } catch (e) {
                if (verbose) console.log(`  HPACK decode error on stream ${frame.streamId}: ${e.message}`);
            }
        }

        if (!parsedRequest) {
            return { reconstructed: null, error: 'Could not parse request headers' };
        }

        // Build normalized transaction object
        // Pass null for extractedCertInfo — the validator adds it after extraction
        const reconstructed = buildNormalizedTransaction(claimed, null, parsedRequest, parsedResponse);
        return { reconstructed, error: null };
    }
}
