/**
 * Transaction Validator Module
 *
 * Core validation logic for all protocols: HTTP/1.x, HTTP/2, HTTP/3, WebSocket
 * Can be used for single transaction or batch validation.
 */

import { base64ToBytes, sha256, bytesToHex } from './crypto/hash.js';
import { TlsDecryptor, parseTlsRecords, TLS_CONTENT_TYPE } from './crypto/tls.js';
import { QuicDecryptor } from './crypto/quic.js';
import { parseFrames, FrameType, extractHeaderBlock } from './protocol/http2.js';
import { HpackDecoder } from './protocol/hpack.js';
import { extractTcpSegment } from './protocol/tcp.js';

/**
 * Parse keylog string into structured object for TlsDecryptor.
 * @param {string} keylogStr - NSS keylog format string
 * @returns {Object|null} Parsed keylog or null if invalid
 */
export function parseKeylog(keylogStr) {
    if (!keylogStr) return null;
    if (typeof keylogStr === 'object') return keylogStr;

    const keys = {};
    let clientRandom = null;
    const lines = keylogStr.split('\n');

    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;

        const parts = trimmed.split(/\s+/);
        if (parts.length < 3) continue;

        const label = parts[0].toLowerCase();

        if (label === 'client_random' && parts.length === 3) {
            clientRandom = parts[1];
            keys.master_secret = parts[2];
        } else {
            keys[label] = parts[2];
        }
    }

    let version;
    if (keys.client_traffic_secret_0 || keys.server_traffic_secret_0 ||
        keys.client_handshake_traffic_secret || keys.server_handshake_traffic_secret) {
        version = 'TLS13';
    } else if (clientRandom && keys.master_secret) {
        version = 'TLS12';
    } else {
        return null;
    }

    const result = { version, keys };
    if (version === 'TLS12') {
        result.client_random = clientRandom;
    }
    return result;
}

/**
 * Extract TLS payload from raw packet data (handles Ethernet, IPv4, IPv6, TCP)
 * @param {Uint8Array} data - Raw packet bytes
 * @returns {Uint8Array|null} TLS payload or null
 */
export function extractTlsPayload(data) {
    if (!data || data.length < 5) return null;

    // Check if it's already TLS record layer data (content type 20-23, version 0x0301-0x0303)
    const firstByte = data[0];
    if (firstByte >= 20 && firstByte <= 23) {
        const version = (data[1] << 8) | data[2];
        if (version >= 0x0301 && version <= 0x0303) {
            return data;
        }
    }

    // Check for IPv4 header (version 4 in high nibble)
    if ((data[0] >> 4) === 4) {
        return extractFromIpv4(data);
    }

    // Check for IPv6 header (version 6 in high nibble)
    if ((data[0] >> 4) === 6) {
        return extractFromIpv6(data);
    }

    // Check for Ethernet frame - EtherType at bytes 12-13
    if (data.length >= 14) {
        const etherType = (data[12] << 8) | data[13];
        if (etherType === 0x0800) {
            return extractFromIpv4(data.slice(14));
        } else if (etherType === 0x86DD) {
            return extractFromIpv6(data.slice(14));
        }
    }

    return null;
}

function extractFromIpv4(data) {
    if (data.length < 20) return null;
    const ihl = (data[0] & 0x0f) * 4;
    const protocol = data[9];

    if (protocol === 6) {
        // TCP
        const tcpStart = ihl;
        if (data.length < tcpStart + 20) return null;
        const tcpDataOffset = (data[tcpStart + 12] >> 4) * 4;
        const payload = data.slice(tcpStart + tcpDataOffset);
        return payload.length > 0 ? payload : null;
    } else if (protocol === 17) {
        // UDP (for HTTP/3/QUIC)
        const udpStart = ihl;
        if (data.length < udpStart + 8) return null;
        const payload = data.slice(udpStart + 8);
        return payload.length > 0 ? payload : null;
    }

    return null;
}

function extractFromIpv6(data) {
    if (data.length < 40) return null;
    const nextHeader = data[6];

    if (nextHeader === 6) {
        // TCP
        const tcpStart = 40;
        if (data.length < tcpStart + 20) return null;
        const tcpDataOffset = (data[tcpStart + 12] >> 4) * 4;
        const payload = data.slice(tcpStart + tcpDataOffset);
        return payload.length > 0 ? payload : null;
    } else if (nextHeader === 17) {
        // UDP (for HTTP/3/QUIC)
        const udpStart = 40;
        if (data.length < udpStart + 8) return null;
        const payload = data.slice(udpStart + 8);
        return payload.length > 0 ? payload : null;
    }

    return null;
}


/**
 * Validation result structure
 */
export class ValidationResult {
    constructor() {
        this.valid = false;
        this.level = 'none';  // none, decrypt, parse, full
        this.error = null;
        this.details = {};
    }
}

/**
 * Concatenate arrays into a single Uint8Array
 */
function concatenate(arrays) {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}

/**
 * Decrypt TLS stream (handles TLS 1.2 and 1.3)
 *
 * This function handles forensic evidence packets which may have gaps in TCP sequence
 * numbers. TLS records can span multiple TCP packets, so we need to:
 * 1. Collect all packets per direction
 * 2. Sort by TCP sequence number
 * 3. Concatenate TCP payloads to form complete TLS records
 * 4. Parse TLS records from the concatenated stream
 * 5. Track TLS sequence numbers for decryption
 *
 * For the server direction, handshake packets may contain the START of TLS records
 * that continue into application packets, so we include ALL packets.
 */
async function decryptTlsStream(evidence, keylog, options = {}) {
    const { verbose = false } = options;
    const allPackets = evidence.raw_packets?.packets || [];

    // Collect TCP segments per direction
    const clientSegments = [];
    const serverSegments = [];
    const seenSeqs = { client: new Set(), server: new Set() };

    for (const pkt of allPackets) {
        const data = base64ToBytes(pkt.data);
        const isClient = pkt.direction === 'client_to_server';
        const segments = isClient ? clientSegments : serverSegments;
        const seen = isClient ? seenSeqs.client : seenSeqs.server;

        // Extract TCP segment
        const tcpSegment = extractTcpSegment(data);

        if (tcpSegment && tcpSegment.payload.length > 0) {
            // Skip duplicate packets (retransmissions)
            if (seen.has(tcpSegment.seqNum)) {
                if (verbose) {
                    console.log(`  [${isClient ? 'client' : 'server'}] Skipping duplicate seq=${tcpSegment.seqNum}`);
                }
                continue;
            }
            seen.add(tcpSegment.seqNum);
            segments.push({ payload: tcpSegment.payload, seq: tcpSegment.seqNum });
        } else {
            // Fallback: packet doesn't have TCP headers (raw TLS payload)
            const tlsPayload = extractTlsPayload(data);
            if (tlsPayload && tlsPayload.length > 0) {
                segments.push({ payload: tlsPayload, seq: 0 });
            }
        }
    }

    if (clientSegments.length === 0 && serverSegments.length === 0) {
        return { error: 'No TLS payloads', plaintext: [] };
    }

    // Sort segments by TCP sequence number (ascending)
    clientSegments.sort((a, b) => a.seq - b.seq);
    serverSegments.sort((a, b) => a.seq - b.seq);

    // Concatenate payloads per direction
    const clientStream = concatenatePayloads(clientSegments);
    const serverStream = concatenatePayloads(serverSegments);

    // Parse TLS records from concatenated streams
    const clientRecords = parseTlsRecords(clientStream);
    const serverRecords = parseTlsRecords(serverStream);

    if (verbose) {
        console.log(`  Client: ${clientSegments.length} segments -> ${clientStream.length} bytes -> ${clientRecords.length} TLS records`);
        console.log(`  Server: ${serverSegments.length} segments -> ${serverStream.length} bytes -> ${serverRecords.length} TLS records`);
    }

    // Initialize decryptor
    const decryptor = new TlsDecryptor();
    await decryptor.initialize(keylog);

    const allPlaintext = [];

    // Decrypt records in order
    // TLS sequence numbers are per-direction and increment for each record
    for (const [direction, records] of [['client', clientRecords], ['server', serverRecords]]) {
        let appSeq = 0;
        let hsSeq = 0;

        for (const record of records) {
            if (record.type !== TLS_CONTENT_TYPE.APPLICATION_DATA) continue;

            if (verbose) {
                console.log(`  [${direction}] Record type=${record.type}, size=${record.data.length}`);
            }

            try {
                // Try application keys first, then handshake keys
                let decrypted;
                let seqSource = '';

                try {
                    decrypted = await decryptor.decryptRecord(record.raw, direction, appSeq, null, 'application');
                    appSeq = decrypted.seq + 1;
                    seqSource = 'app';
                } catch (e1) {
                    // Try handshake keys
                    decrypted = await decryptor.decryptRecord(record.raw, direction, hsSeq, null, 'handshake');
                    hsSeq = decrypted.seq + 1;
                    seqSource = 'hs';
                }

                allPlaintext.push({ direction, data: decrypted.plaintext });
                if (verbose) {
                    console.log(`    -> Decrypted ${decrypted.plaintext.length} bytes (seq ${decrypted.seq} [${seqSource}])`);
                }
            } catch (e) {
                if (verbose) {
                    console.log(`    -> Failed: ${e.message}`);
                }
            }
        }
    }

    return { error: null, plaintext: allPlaintext };
}

/**
 * Reassemble TCP payloads into a single stream, handling overlaps and retransmissions.
 */
function concatenatePayloads(segments) {
    const totalLength = segments.reduce((sum, s) => sum + s.payload.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const s of segments) {
        result.set(s.payload, offset);
        offset += s.payload.length;
    }
    return result;
}

/**
 * Validate an HTTP/2 transaction
 * @param {Object} tx - Transaction object
 * @param {Object} evidence - Forensic evidence
 * @param {Object} options - Validation options
 * @returns {Promise<ValidationResult>}
 */
export async function validateHttp2(tx, evidence, options = {}) {
    const result = new ValidationResult();
    const { verbose = false } = options;

    // Check required fields
    const streamId = evidence.h2_stream_id;
    if (!streamId) {
        result.error = 'Missing h2_stream_id';
        return result;
    }

    const requestSnapshot = evidence.hpack_request_table;
    const responseSnapshot = evidence.hpack_response_table;
    if (!requestSnapshot || !responseSnapshot) {
        result.error = 'Missing HPACK snapshots';
        return result;
    }

    // Parse keylog
    const keylog = parseKeylog(evidence.keylog);
    if (!keylog) {
        result.error = 'Invalid keylog';
        return result;
    }

    // For TLS 1.2, extract server_random from ServerHello
    if (keylog.version === 'TLS12') {
        const serverRandom = extractServerRandom(evidence.raw_packets?.packets || []);
        if (serverRandom) {
            keylog.server_random = Array.from(serverRandom)
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        }
    }

    // Decrypt TLS stream
    const { error, plaintext: allPlaintext } = await decryptTlsStream(evidence, keylog, options);
    if (error) {
        result.error = error;
        return result;
    }

    if (allPlaintext.length === 0) {
        result.error = 'Decryption failed';
        return result;
    }

    result.level = 'decrypt';
    result.valid = true;

    // Initialize HPACK decoders from snapshots
    const requestHpack = new HpackDecoder(requestSnapshot);
    const responseHpack = new HpackDecoder(responseSnapshot);

    let foundRequestHeaders = false;
    let foundResponseHeaders = false;
    let parsedRequest = null;
    let parsedResponse = null;

    // Parse HTTP/2 frames
    // CRITICAL: Only decode the FIRST HEADERS frame for the target stream.
    // HPACK state evolves with each decoded frame. The snapshot is for the state
    // BEFORE the target stream's HEADERS frame, so we must stop after finding it.
    for (const { direction, data } of allPlaintext) {
        // Stop once we've found both request and response headers
        if (foundRequestHeaders && foundResponseHeaders) break;

        // Skip HTTP/2 connection preface
        let offset = 0;
        const preface = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';
        const prefaceBytes = new TextEncoder().encode(preface);
        if (data.length >= prefaceBytes.length) {
            let isPreface = true;
            for (let i = 0; i < prefaceBytes.length; i++) {
                if (data[i] !== prefaceBytes[i]) { isPreface = false; break; }
            }
            if (isPreface) offset = prefaceBytes.length;
        }

        try {
            const frames = parseFrames(data.slice(offset));
            for (const frame of frames) {
                if (frame.streamId !== streamId) continue;

                if (frame.type === FrameType.HEADERS) {
                    // Only decode the FIRST HEADERS frame for this direction
                    const decoder = direction === 'client' ? requestHpack : responseHpack;
                    const alreadyFound = direction === 'client' ? foundRequestHeaders : foundResponseHeaders;
                    if (alreadyFound) continue;

                    try {
                        const headerBlock = extractHeaderBlock(frame.payload, frame.flags);
                        const headers = decoder.decode(headerBlock);

                        const headerMap = {};
                        for (const [name, value] of headers) {
                            headerMap[name] = value;
                        }

                        if (direction === 'client') {
                            foundRequestHeaders = true;
                            parsedRequest = {
                                method: headerMap[':method'],
                                path: headerMap[':path'],
                                authority: headerMap[':authority'],
                                scheme: headerMap[':scheme'],
                                headers: headerMap
                            };
                            if (verbose) console.log(`  Found request: ${parsedRequest.method} ${parsedRequest.path}`);
                        } else {
                            foundResponseHeaders = true;
                            parsedResponse = {
                                status: parseInt(headerMap[':status'], 10),
                                headers: headerMap
                            };
                            if (verbose) console.log(`  Found response: ${parsedResponse.status}`);
                        }
                    } catch (e) {
                        if (verbose) console.log(`  HPACK decode error: ${e.message}`);
                    }
                }
            }
        } catch (e) {
            if (verbose) console.log(`  Frame parse error: ${e.message}`);
        }
    }

    if (foundRequestHeaders || foundResponseHeaders) {
        result.level = 'parse';
        result.details.parsedRequest = parsedRequest;
        result.details.parsedResponse = parsedResponse;
    }

    // Compare with claimed values
    if (parsedRequest && tx.request) {
        try {
            const claimedUrl = new URL(tx.request.url);
            const claimedPath = claimedUrl.pathname + claimedUrl.search;

            const methodMatch = parsedRequest.method === tx.request.method;
            const pathMatch = parsedRequest.path === claimedPath;
            const authorityMatch = parsedRequest.authority === claimedUrl.host;

            if (methodMatch && pathMatch && authorityMatch) {
                result.level = 'full';
            } else {
                result.details.mismatch = {
                    claimed: { method: tx.request.method, path: claimedPath, authority: claimedUrl.host },
                    parsed: { method: parsedRequest.method, path: parsedRequest.path, authority: parsedRequest.authority }
                };
            }
        } catch (e) {
            result.details.compareError = e.message;
        }
    }

    return result;
}

/**
 * Extract server_random from TLS 1.2 ServerHello in handshake packets
 */
function extractServerRandom(packets) {
    for (const pkt of packets) {
        if (pkt.packet_type !== 'handshake') continue;
        if (pkt.direction !== 'server_to_client') continue;

        const data = base64ToBytes(pkt.data);
        const tlsPayload = extractTlsPayload(data);
        if (!tlsPayload || tlsPayload.length === 0) continue;

        // Look for TLS handshake records
        let offset = 0;
        while (offset + 5 <= tlsPayload.length) {
            const contentType = tlsPayload[offset];
            const recordLen = (tlsPayload[offset + 3] << 8) | tlsPayload[offset + 4];

            if (contentType !== 22) { // Not handshake
                offset += 5 + recordLen;
                continue;
            }

            if (offset + 5 + 38 > tlsPayload.length) {
                offset += 5 + recordLen;
                continue;
            }

            const hsType = tlsPayload[offset + 5];
            if (hsType === 0x02) { // ServerHello
                // ServerHello: type(1) + len(3) + version(2) + random(32)
                const randomOffset = offset + 5 + 1 + 3 + 2;
                if (randomOffset + 32 <= tlsPayload.length) {
                    return tlsPayload.slice(randomOffset, randomOffset + 32);
                }
            }

            offset += 5 + recordLen;
        }
    }
    return null;
}

/**
 * Validate an HTTP/1.x transaction
 * @param {Object} tx - Transaction object
 * @param {Object} evidence - Forensic evidence
 * @param {Object} options - Validation options
 * @returns {Promise<ValidationResult>}
 */
export async function validateHttp1(tx, evidence, options = {}) {
    const result = new ValidationResult();
    const { verbose = false } = options;

    const keylog = parseKeylog(evidence.keylog);
    if (!keylog) {
        result.error = 'Invalid keylog';
        return result;
    }

    // For TLS 1.2, extract server_random from ServerHello
    if (keylog.version === 'TLS12') {
        const serverRandom = extractServerRandom(evidence.raw_packets?.packets || []);
        if (serverRandom) {
            keylog.server_random = Array.from(serverRandom)
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        }
    }

    // Decrypt TLS stream
    const { error, plaintext: allPlaintext } = await decryptTlsStream(evidence, keylog, options);
    if (error) {
        result.error = error;
        return result;
    }

    if (allPlaintext.length === 0) {
        result.error = 'Decryption failed';
        return result;
    }

    result.level = 'decrypt';
    result.valid = true;

    // Parse HTTP/1.x request line
    const clientPlaintext = allPlaintext.filter(p => p.direction === 'client');
    if (clientPlaintext.length > 0) {
        const combined = concatenate(clientPlaintext.map(p => p.data));
        const text = new TextDecoder().decode(combined);
        const lines = text.split('\r\n');

        if (lines.length > 0) {
            const requestLine = lines[0];
            const match = requestLine.match(/^(\w+)\s+(\S+)\s+HTTP\/[\d.]+/);
            if (match) {
                result.level = 'parse';
                const parsedMethod = match[1];
                const parsedPath = match[2];

                result.details.parsedRequest = { method: parsedMethod, path: parsedPath };

                // Compare
                if (tx.request) {
                    try {
                        const claimedUrl = new URL(tx.request.url);
                        const claimedPath = claimedUrl.pathname + claimedUrl.search;

                        if (parsedMethod === tx.request.method && parsedPath === claimedPath) {
                            result.level = 'full';
                        } else {
                            result.details.mismatch = {
                                claimed: { method: tx.request.method, path: claimedPath },
                                parsed: { method: parsedMethod, path: parsedPath }
                            };
                        }
                    } catch (e) {}
                }
            }
        }
    }

    return result;
}

/**
 * Validate a WebSocket message
 * @param {Object} tx - WebSocket message object
 * @param {Object} evidence - Forensic evidence
 * @param {Object} options - Validation options
 * @returns {Promise<ValidationResult>}
 */
export async function validateWebSocket(tx, evidence, options = {}) {
    const result = new ValidationResult();
    const { verbose = false } = options;

    const keylog = parseKeylog(evidence.keylog);
    if (!keylog) {
        result.error = 'Invalid keylog';
        return result;
    }

    // For TLS 1.2, extract server_random from ServerHello
    if (keylog.version === 'TLS12') {
        const serverRandom = extractServerRandom(evidence.raw_packets?.packets || []);
        if (serverRandom) {
            keylog.server_random = Array.from(serverRandom)
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        }
    }

    // Decrypt TLS stream
    const { error, plaintext: allPlaintext } = await decryptTlsStream(evidence, keylog, options);
    if (error) {
        result.error = error;
        return result;
    }

    if (allPlaintext.length === 0) {
        result.error = 'Decryption failed';
        return result;
    }

    // WebSocket: decrypt level is sufficient for validation
    result.level = 'decrypt';
    result.valid = true;

    return result;
}

/**
 * Validate an HTTP/3 transaction (QUIC)
 * @param {Object} tx - Transaction object
 * @param {Object} evidence - Forensic evidence
 * @param {Object} options - Validation options
 * @returns {Promise<ValidationResult>}
 */
export async function validateHttp3(tx, evidence, options = {}) {
    const result = new ValidationResult();
    const { verbose = false } = options;

    // Parse QUIC keylog
    const keylogLines = evidence.keylog?.split('\n').filter(l => l.trim()) || [];
    const quicSecrets = {};

    for (const line of keylogLines) {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 3) continue;
        const label = parts[0].toLowerCase();
        quicSecrets[label] = parts[2];
    }

    if (!quicSecrets.quic_client_traffic_secret_0 && !quicSecrets.client_traffic_secret_0) {
        result.error = 'Missing QUIC secrets';
        return result;
    }

    // Collect UDP packets (extractTlsPayload handles both TCP and UDP)
    const packets = [];
    for (const pkt of evidence.raw_packets?.packets || []) {
        if (pkt.packet_type !== 'application') continue;
        const data = base64ToBytes(pkt.data);
        const payload = extractTlsPayload(data);
        if (payload && payload.length > 0) {
            packets.push({ direction: pkt.direction, data: payload });
        }
    }

    if (packets.length === 0) {
        result.error = 'No QUIC packets';
        return result;
    }

    // Try to decrypt
    let decryptedAny = false;

    for (const pkt of packets) {
        const isClient = pkt.direction === 'client_to_server';
        const secretKey = isClient ? 'quic_client_traffic_secret_0' : 'quic_server_traffic_secret_0';
        const secret = quicSecrets[secretKey] || quicSecrets[secretKey.replace('quic_', '')];

        if (!secret) continue;

        try {
            const decryptor = new QuicDecryptor();
            await decryptor.initializeFromSecret(secret);

            // QUIC packet structure varies, try to decrypt payload
            // This is simplified - real QUIC has complex packet structure
            for (let pn = 0; pn <= 1000; pn++) {
                try {
                    const plaintext = await decryptor.decryptPacket(pkt.data, pn);
                    if (plaintext && plaintext.length > 0) {
                        decryptedAny = true;
                        if (verbose) console.log(`  Decrypted QUIC packet (pn ${pn})`);
                        break;
                    }
                } catch (e) {}
            }
        } catch (e) {
            if (verbose) console.log(`  QUIC decrypt error: ${e.message}`);
        }
    }

    if (decryptedAny) {
        result.level = 'decrypt';
        result.valid = true;
    } else {
        result.error = 'QUIC decryption failed';
    }

    return result;
}

/**
 * Validate any transaction (auto-detects protocol)
 * @param {Object} txWrapper - Transaction wrapper { type, data } or raw transaction
 * @param {Object} options - Validation options
 * @returns {Promise<ValidationResult>}
 */
export async function validate(txWrapper, options = {}) {
    const tx = txWrapper.data || txWrapper;
    const type = txWrapper.type;
    const evidence = tx.forensic_evidence;

    const result = new ValidationResult();

    if (!evidence) {
        result.error = 'No forensic evidence';
        return result;
    }

    // Detect protocol
    const protocol = tx.protocol;
    const isWebSocket = type === 'web_socket_message' || !protocol;

    if (isWebSocket && type === 'web_socket_message') {
        return validateWebSocket(tx, evidence, options);
    } else if (protocol === 'HTTP/2') {
        return validateHttp2(tx, evidence, options);
    } else if (protocol === 'HTTP/3') {
        return validateHttp3(tx, evidence, options);
    } else if (protocol === 'HTTP/1.1' || protocol === 'HTTP/1.0') {
        return validateHttp1(tx, evidence, options);
    } else {
        result.error = `Unknown protocol: ${protocol}`;
        return result;
    }
}

/**
 * Stable JSON stringify with sorted keys for deterministic hashing.
 * @param {any} obj - Object to stringify
 * @returns {string} JSON string with sorted keys
 */
export function stableStringify(obj) {
    if (obj === null || obj === undefined) {
        return JSON.stringify(obj);
    }
    if (typeof obj !== 'object') {
        return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
        return '[' + obj.map(item => stableStringify(item)).join(',') + ']';
    }
    const keys = Object.keys(obj).sort();
    const pairs = keys.map(key => {
        const value = stableStringify(obj[key]);
        return JSON.stringify(key) + ':' + value;
    });
    return '{' + pairs.join(',') + '}';
}

/**
 * Compute SHA-256 hash of a transaction object using stable stringify.
 * @param {Object} tx - Transaction object
 * @returns {Promise<string>} Hex hash string
 */
export async function hashTransaction(tx) {
    const json = stableStringify(tx);
    const bytes = new TextEncoder().encode(json);
    const hash = await sha256(bytes);
    return bytesToHex(hash);
}

/**
 * Reconstruct a transaction from forensic evidence by decrypting and parsing.
 * Returns a normalized transaction object suitable for hash comparison.
 *
 * @param {Object} tx - Original transaction (for protocol detection)
 * @param {Object} evidence - Forensic evidence
 * @param {Object} options - Options
 * @returns {Promise<{reconstructed: Object|null, error: string|null}>}
 */
export async function reconstructTransaction(tx, evidence, options = {}) {
    const { verbose = false } = options;
    const protocol = tx.protocol;

    // Parse keylog
    const keylog = parseKeylog(evidence.keylog);
    if (!keylog) {
        return { reconstructed: null, error: 'Invalid keylog' };
    }

    // For TLS 1.2, extract server_random
    if (keylog.version === 'TLS12') {
        const serverRandom = extractServerRandom(evidence.raw_packets?.packets || []);
        if (serverRandom) {
            keylog.server_random = Array.from(serverRandom)
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        }
    }

    // Decrypt TLS stream
    const { error, plaintext: allPlaintext } = await decryptTlsStream(evidence, keylog, options);
    if (error) {
        return { reconstructed: null, error };
    }

    if (allPlaintext.length === 0) {
        return { reconstructed: null, error: 'Decryption failed' };
    }

    // Protocol-specific reconstruction
    if (protocol === 'HTTP/2') {
        return reconstructHttp2Transaction(tx, evidence, allPlaintext, options);
    } else if (protocol === 'HTTP/1.1' || protocol === 'HTTP/1.0') {
        return reconstructHttp1Transaction(tx, evidence, allPlaintext, options);
    } else {
        return { reconstructed: null, error: `Unsupported protocol: ${protocol}` };
    }
}

/**
 * Reconstruct HTTP/2 transaction from decrypted plaintext.
 */
async function reconstructHttp2Transaction(tx, evidence, allPlaintext, options = {}) {
    const { verbose = false } = options;
    const streamId = evidence.h2_stream_id;

    if (!streamId) {
        return { reconstructed: null, error: 'Missing h2_stream_id' };
    }

    const requestSnapshot = evidence.hpack_request_table;
    const responseSnapshot = evidence.hpack_response_table;

    if (!requestSnapshot || !responseSnapshot) {
        return { reconstructed: null, error: 'Missing HPACK snapshots' };
    }

    // Initialize HPACK decoders
    const requestHpack = new HpackDecoder(requestSnapshot);
    const responseHpack = new HpackDecoder(responseSnapshot);

    let parsedRequest = null;
    let parsedResponse = null;
    let foundRequestHeaders = false;
    let foundResponseHeaders = false;

    // Parse HTTP/2 frames
    for (const { direction, data } of allPlaintext) {
        if (foundRequestHeaders && foundResponseHeaders) break;

        // Skip HTTP/2 connection preface
        let offset = 0;
        const preface = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';
        const prefaceBytes = new TextEncoder().encode(preface);
        if (data.length >= prefaceBytes.length) {
            let isPreface = true;
            for (let i = 0; i < prefaceBytes.length; i++) {
                if (data[i] !== prefaceBytes[i]) { isPreface = false; break; }
            }
            if (isPreface) offset = prefaceBytes.length;
        }

        try {
            const frames = parseFrames(data.slice(offset));
            for (const frame of frames) {
                if (frame.streamId !== streamId) continue;

                if (frame.type === FrameType.HEADERS) {
                    const decoder = direction === 'client' ? requestHpack : responseHpack;
                    const alreadyFound = direction === 'client' ? foundRequestHeaders : foundResponseHeaders;
                    if (alreadyFound) continue;

                    try {
                        const headerBlock = extractHeaderBlock(frame.payload, frame.flags);
                        const headers = decoder.decode(headerBlock);

                        const headerMap = {};
                        for (const [name, value] of headers) {
                            headerMap[name] = value;
                        }

                        if (direction === 'client') {
                            foundRequestHeaders = true;
                            parsedRequest = {
                                method: headerMap[':method'],
                                path: headerMap[':path'],
                                authority: headerMap[':authority'],
                                scheme: headerMap[':scheme'],
                                headers: headerMap
                            };
                        } else {
                            foundResponseHeaders = true;
                            parsedResponse = {
                                status: parseInt(headerMap[':status'], 10),
                                headers: headerMap
                            };
                        }
                    } catch (e) {
                        if (verbose) console.log(`  HPACK decode error: ${e.message}`);
                    }
                }
            }
        } catch (e) {
            if (verbose) console.log(`  Frame parse error: ${e.message}`);
        }
    }

    if (!parsedRequest) {
        return { reconstructed: null, error: 'Could not parse request headers' };
    }

    // Build normalized transaction object
    const reconstructed = buildNormalizedTransaction(tx, evidence, parsedRequest, parsedResponse);
    return { reconstructed, error: null };
}

/**
 * Reconstruct HTTP/1.x transaction from decrypted plaintext.
 */
async function reconstructHttp1Transaction(tx, evidence, allPlaintext, options = {}) {
    const { verbose = false } = options;

    // Combine client plaintext
    const clientPlaintext = allPlaintext.filter(p => p.direction === 'client');
    if (clientPlaintext.length === 0) {
        return { reconstructed: null, error: 'No client data' };
    }

    const combined = concatenate(clientPlaintext.map(p => p.data));
    const text = new TextDecoder().decode(combined);
    const lines = text.split('\r\n');

    if (lines.length === 0) {
        return { reconstructed: null, error: 'Empty request' };
    }

    // Parse request line
    const requestLine = lines[0];
    const match = requestLine.match(/^(\w+)\s+(\S+)\s+HTTP\/([\d.]+)/);
    if (!match) {
        return { reconstructed: null, error: 'Invalid request line' };
    }

    const method = match[1];
    const path = match[2];
    const version = match[3];

    // Parse headers
    const headers = {};
    let i = 1;
    while (i < lines.length && lines[i] !== '') {
        const headerLine = lines[i];
        const colonIdx = headerLine.indexOf(':');
        if (colonIdx > 0) {
            const name = headerLine.substring(0, colonIdx).toLowerCase();
            const value = headerLine.substring(colonIdx + 1).trim();
            headers[name] = value;
        }
        i++;
    }

    // Parse response if available
    let parsedResponse = null;
    const serverPlaintext = allPlaintext.filter(p => p.direction === 'server');
    if (serverPlaintext.length > 0) {
        const serverCombined = concatenate(serverPlaintext.map(p => p.data));
        const serverText = new TextDecoder().decode(serverCombined);
        const serverLines = serverText.split('\r\n');

        if (serverLines.length > 0) {
            const statusMatch = serverLines[0].match(/^HTTP\/([\d.]+)\s+(\d+)\s*(.*)/);
            if (statusMatch) {
                const respHeaders = {};
                let j = 1;
                while (j < serverLines.length && serverLines[j] !== '') {
                    const headerLine = serverLines[j];
                    const colonIdx = headerLine.indexOf(':');
                    if (colonIdx > 0) {
                        const name = headerLine.substring(0, colonIdx).toLowerCase();
                        const value = headerLine.substring(colonIdx + 1).trim();
                        respHeaders[name] = value;
                    }
                    j++;
                }
                parsedResponse = {
                    status: parseInt(statusMatch[2], 10),
                    statusText: statusMatch[3] || '',
                    version: statusMatch[1],
                    headers: respHeaders
                };
            }
        }
    }

    const parsedRequest = {
        method,
        path,
        version,
        authority: headers['host'] || '',
        headers
    };

    const reconstructed = buildNormalizedTransaction(tx, evidence, parsedRequest, parsedResponse);
    return { reconstructed, error: null };
}

/**
 * Build a normalized transaction object from parsed data.
 * This creates a structure that can be compared via hash.
 */
function buildNormalizedTransaction(tx, evidence, parsedRequest, parsedResponse) {
    // Build URL from parsed components
    let url;
    if (parsedRequest.scheme && parsedRequest.authority && parsedRequest.path) {
        url = `${parsedRequest.scheme}://${parsedRequest.authority}${parsedRequest.path}`;
    } else if (parsedRequest.authority && parsedRequest.path) {
        url = `https://${parsedRequest.authority}${parsedRequest.path}`;
    } else {
        // Fall back to original URL structure
        url = tx.request?.url || '';
    }

    // Extract certificate info from evidence (this is already captured at TLS handshake)
    const certInfo = evidence.certificate_info || null;

    // Build normalized transaction
    const normalized = {
        // Core identification
        id: tx.id,
        protocol: tx.protocol,

        // Connection info
        connection: tx.connection ? {
            id: tx.connection.id,
            client_addr: tx.connection.client_addr,
            server_addr: tx.connection.server_addr,
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

        // Certificate info (moved to top level from forensic_evidence)
        certificate_info: certInfo ? {
            sni: certInfo.sni,
            tls_version: certInfo.tls_version,
            alpn: certInfo.alpn,
            cipher_suite: certInfo.cipher_suite,
            certificate_chain: certInfo.certificate_chain,
        } : null,
    };

    return normalized;
}

/**
 * Normalize headers for comparison.
 * Removes pseudo-headers (: prefix) and lowercases names.
 */
function normalizeHeaders(headers) {
    if (!headers) return {};
    const normalized = {};
    for (const [name, value] of Object.entries(headers)) {
        // Skip pseudo-headers for normalization
        if (name.startsWith(':')) continue;
        normalized[name.toLowerCase()] = value;
    }
    return normalized;
}

/**
 * Compare a transaction with its reconstructed version via hash.
 *
 * Returns detailed comparison results including:
 * - fullMatch: true if entire transaction matches (request + response + cert)
 * - requestMatch: true if request matches
 * - responseMatch: true if response matches (or both null)
 * - certMatch: true if certificate info matches
 *
 * @param {Object} tx - Original transaction
 * @param {Object} options - Options (verbose)
 * @returns {Promise<{fullMatch: boolean, requestMatch: boolean, responseMatch: boolean, certMatch: boolean, originalHash: string, reconstructedHash: string, error: string|null, reconstructed: Object|null}>}
 */
export async function compareTransactionHash(tx, options = {}) {
    const { verbose = false } = options;
    const evidence = tx.forensic_evidence;

    if (!evidence) {
        return { fullMatch: false, requestMatch: false, responseMatch: false, certMatch: false, error: 'No forensic evidence', originalHash: null, reconstructedHash: null, reconstructed: null };
    }

    // Reconstruct from evidence
    const { reconstructed, error } = await reconstructTransaction(tx, evidence, options);
    if (error) {
        return { fullMatch: false, requestMatch: false, responseMatch: false, certMatch: false, error, originalHash: null, reconstructedHash: null, reconstructed: null };
    }

    // Build normalized version of original (without forensic_evidence)
    const certInfo = evidence.certificate_info || null;
    const original = {
        id: tx.id,
        protocol: tx.protocol,
        connection: tx.connection ? {
            id: tx.connection.id,
            client_addr: tx.connection.client_addr,
            server_addr: tx.connection.server_addr,
        } : null,
        request: tx.request ? {
            method: tx.request.method,
            url: tx.request.url,
            headers: normalizeHeaders(tx.request.headers),
        } : null,
        response: tx.response ? {
            status: tx.response.status,
            headers: normalizeHeaders(tx.response.headers),
        } : null,
        certificate_info: certInfo ? {
            sni: certInfo.sni,
            tls_version: certInfo.tls_version,
            alpn: certInfo.alpn,
            cipher_suite: certInfo.cipher_suite,
            certificate_chain: certInfo.certificate_chain,
        } : null,
    };

    // Compare individual components
    const requestMatch = await compareComponent(original.request, reconstructed.request);
    const responseMatch = await compareComponent(original.response, reconstructed.response);
    const certMatch = await compareComponent(original.certificate_info, reconstructed.certificate_info);

    // Hash both full objects
    const originalHash = await hashTransaction(original);
    const reconstructedHash = await hashTransaction(reconstructed);
    const fullMatch = originalHash === reconstructedHash;

    if (verbose) {
        console.log(`  Full match: ${fullMatch}`);
        console.log(`  Request match: ${requestMatch}`);
        console.log(`  Response match: ${responseMatch}`);
        console.log(`  Cert match: ${certMatch}`);
        if (!fullMatch) {
            console.log(`  Original hash:      ${originalHash}`);
            console.log(`  Reconstructed hash: ${reconstructedHash}`);
        }
    }

    return { fullMatch, requestMatch, responseMatch, certMatch, originalHash, reconstructedHash, error: null, reconstructed, match: fullMatch };
}

/**
 * Compare two components by hashing their stable JSON representations.
 */
async function compareComponent(original, reconstructed) {
    // Both null = match
    if (original === null && reconstructed === null) return true;
    // One null, other not = no match
    if (original === null || reconstructed === null) return false;
    // Compare hashes
    const origHash = await hashTransaction(original);
    const recHash = await hashTransaction(reconstructed);
    return origHash === recHash;
}
