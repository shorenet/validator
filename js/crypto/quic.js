/**
 * QUIC decryption for HTTP/3 traffic.
 *
 * QUIC uses a different encryption scheme than TLS records:
 * - Header protection (AES-ECB mask)
 * - Packet number reconstruction
 * - Per-packet nonce (IV XOR packet number)
 */

import { hexToBytes, bytesToHex } from './hash.js';

/**
 * HKDF-Expand function for QUIC key derivation.
 * Uses "tls13 quic " prefix for QUIC-specific labels.
 *
 * @param {Uint8Array} secret - Traffic secret
 * @param {string} label - Label (without prefix)
 * @param {Uint8Array} context - Context (usually empty)
 * @param {number} length - Output length
 * @returns {Promise<Uint8Array>}
 */
async function quicHkdfExpandLabel(secret, label, context, length) {
    // QUIC uses "tls13 quic <label>" format
    const fullLabel = new TextEncoder().encode('tls13 quic ' + label);

    // HKDF label structure
    const hkdfLabel = new Uint8Array(2 + 1 + fullLabel.length + 1 + context.length);
    hkdfLabel[0] = (length >> 8) & 0xff;
    hkdfLabel[1] = length & 0xff;
    hkdfLabel[2] = fullLabel.length;
    hkdfLabel.set(fullLabel, 3);
    hkdfLabel[3 + fullLabel.length] = context.length;
    hkdfLabel.set(context, 3 + fullLabel.length + 1);

    // HKDF-Expand using HMAC-SHA256
    const hmacKey = await crypto.subtle.importKey(
        'raw',
        secret,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );

    const hashLen = 32;
    const n = Math.ceil(length / hashLen);
    const okm = new Uint8Array(n * hashLen);
    let t = new Uint8Array(0);

    for (let i = 1; i <= n; i++) {
        const input = new Uint8Array(t.length + hkdfLabel.length + 1);
        input.set(t, 0);
        input.set(hkdfLabel, t.length);
        input[t.length + hkdfLabel.length] = i;

        const sig = await crypto.subtle.sign('HMAC', hmacKey, input);
        t = new Uint8Array(sig);
        okm.set(t, (i - 1) * hashLen);
    }

    return okm.slice(0, length);
}

/**
 * Derive QUIC encryption keys from a traffic secret.
 *
 * @param {Uint8Array} secret - Traffic secret (32 bytes)
 * @returns {Promise<{key: CryptoKey, iv: Uint8Array, hpKey: CryptoKey}>}
 */
export async function deriveQuicKeys(secret) {
    const keyBytes = await quicHkdfExpandLabel(secret, 'key', new Uint8Array(0), 16);
    const iv = await quicHkdfExpandLabel(secret, 'iv', new Uint8Array(0), 12);
    const hpKeyBytes = await quicHkdfExpandLabel(secret, 'hp', new Uint8Array(0), 16);

    const key = await crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );

    const hpKey = await crypto.subtle.importKey(
        'raw',
        hpKeyBytes,
        { name: 'AES-CBC' },  // We'll use ECB mode by encrypting a single block
        true,  // Need to export for ECB simulation
        ['encrypt']
    );

    return { key, keyBytes, iv, hpKey, hpKeyBytes };
}

/**
 * Generate header protection mask using AES-ECB.
 * Web Crypto doesn't support ECB, so we simulate it.
 *
 * @param {Uint8Array} hpKeyBytes - 16-byte HP key
 * @param {Uint8Array} sample - 16-byte sample
 * @returns {Promise<Uint8Array>} 16-byte mask
 */
async function generateHpMask(hpKeyBytes, sample) {
    // Import as raw AES key for ECB simulation
    // We use AES-CBC with zero IV to encrypt a single block, which is equivalent to ECB
    const key = await crypto.subtle.importKey(
        'raw',
        hpKeyBytes,
        { name: 'AES-CBC' },
        false,
        ['encrypt']
    );

    const zeroIv = new Uint8Array(16);
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-CBC', iv: zeroIv },
        key,
        sample
    );

    // The first 16 bytes are our ECB output (before padding)
    return new Uint8Array(encrypted).slice(0, 16);
}

/**
 * Remove QUIC header protection.
 *
 * @param {Uint8Array} data - Mutable packet data
 * @param {number} pnOffset - Offset where packet number starts
 * @param {Uint8Array} hpKeyBytes - HP key bytes
 * @returns {Promise<{pnLen: number, truncatedPn: number}|null>}
 */
async function removeHeaderProtection(data, pnOffset, hpKeyBytes) {
    if (pnOffset + 4 + 16 > data.length) {
        return null;
    }

    // Sample is 16 bytes starting at pnOffset + 4
    const sample = data.slice(pnOffset + 4, pnOffset + 4 + 16);

    // Generate mask
    const mask = await generateHpMask(hpKeyBytes, sample);

    // Determine if long or short header
    const isLong = (data[0] & 0x80) !== 0;

    // Remove protection from first byte
    if (isLong) {
        data[0] ^= mask[0] & 0x0f;
    } else {
        data[0] ^= mask[0] & 0x1f;
    }

    // Get packet number length from first byte
    const pnLen = (data[0] & 0x03) + 1;

    // Remove protection from packet number bytes
    for (let i = 0; i < pnLen; i++) {
        data[pnOffset + i] ^= mask[1 + i];
    }

    // Extract truncated packet number
    let truncatedPn = 0;
    for (let i = 0; i < pnLen; i++) {
        truncatedPn = (truncatedPn << 8) | data[pnOffset + i];
    }

    return { pnLen, truncatedPn };
}

/**
 * Reconstruct full packet number from truncated value.
 *
 * @param {number} largestPn - Largest packet number seen so far
 * @param {number} truncatedPn - Truncated packet number from header
 * @param {number} pnBits - Number of bits in truncated PN (pnLen * 8)
 * @returns {number}
 */
function reconstructPacketNumber(largestPn, truncatedPn, pnBits) {
    const expectedPn = largestPn + 1;
    const pnWin = 1 << pnBits;
    const pnHwin = pnWin >> 1;
    const pnMask = pnWin - 1;

    let candidatePn = (expectedPn & ~pnMask) | truncatedPn;

    if (candidatePn <= expectedPn - pnHwin && candidatePn < (1 << 62) - pnWin) {
        return candidatePn + pnWin;
    } else if (candidatePn > expectedPn + pnHwin && candidatePn >= pnWin) {
        return candidatePn - pnWin;
    }
    return candidatePn;
}

/**
 * Parse a QUIC variable-length integer.
 *
 * @param {Uint8Array} data - Data buffer
 * @param {number} offset - Starting offset
 * @returns {{value: number, length: number}|null}
 */
function parseVarint(data, offset) {
    if (offset >= data.length) return null;

    const first = data[offset];
    const type = (first & 0xc0) >> 6;

    if (type === 0) {
        return { value: first & 0x3f, length: 1 };
    } else if (type === 1) {
        if (offset + 2 > data.length) return null;
        return { value: ((first & 0x3f) << 8) | data[offset + 1], length: 2 };
    } else if (type === 2) {
        if (offset + 4 > data.length) return null;
        return {
            value: ((first & 0x3f) << 24) | (data[offset + 1] << 16) |
                   (data[offset + 2] << 8) | data[offset + 3],
            length: 4
        };
    } else {
        if (offset + 8 > data.length) return null;
        // JavaScript can't handle 62-bit integers precisely, but this is rare
        return {
            value: ((first & 0x3f) * Math.pow(2, 56)) +
                   (data[offset + 1] * Math.pow(2, 48)) +
                   (data[offset + 2] * Math.pow(2, 40)) +
                   (data[offset + 3] * Math.pow(2, 32)) +
                   ((data[offset + 4] << 24) | (data[offset + 5] << 16) |
                    (data[offset + 6] << 8) | data[offset + 7]),
            length: 8
        };
    }
}

/**
 * Decrypt a QUIC packet.
 *
 * @param {Uint8Array} data - Raw packet data
 * @param {{key: CryptoKey, keyBytes: Uint8Array, iv: Uint8Array, hpKey: CryptoKey, hpKeyBytes: Uint8Array}} keys - QUIC keys
 * @param {number} pnOffset - Packet number offset in header
 * @param {number} largestPn - Largest packet number seen
 * @returns {Promise<{plaintext: Uint8Array, packetNumber: number}|null>}
 */
async function decryptQuicPacket(data, keys, pnOffset, largestPn = 0) {
    if (pnOffset + 4 + 16 > data.length) {
        return null;
    }

    // Make mutable copy
    const dataCopy = new Uint8Array(data);

    // Remove header protection
    const hpResult = await removeHeaderProtection(dataCopy, pnOffset, keys.hpKeyBytes);
    if (!hpResult) return null;

    const { pnLen, truncatedPn } = hpResult;

    // Reconstruct packet number
    const packetNumber = reconstructPacketNumber(largestPn, truncatedPn, pnLen * 8);

    // Build nonce: IV XOR packet_number (right-aligned in 12 bytes)
    // Use BigInt because JavaScript >>> only works on 32-bit integers
    const nonce = new Uint8Array(keys.iv);
    const pnBigInt = BigInt(packetNumber);
    for (let i = 0; i < 8; i++) {
        const shift = BigInt((7 - i) * 8);
        nonce[4 + i] ^= Number((pnBigInt >> shift) & 0xffn);
    }

    // Payload starts after header + packet number
    const payloadStart = pnOffset + pnLen;
    if (payloadStart >= dataCopy.length) {
        return null;
    }

    const ciphertext = dataCopy.slice(payloadStart);

    // AAD is the decrypted header (up to and including packet number)
    const aad = dataCopy.slice(0, payloadStart);

    try {
        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
            keys.key,
            ciphertext
        );
        return { plaintext: new Uint8Array(plaintext), packetNumber };
    } catch (e) {
        return null;
    }
}

/**
 * Get packet number offset for different QUIC packet types.
 *
 * Long header format (Initial, 0-RTT, Handshake):
 * - First byte: Form(1) | Fixed(1) | Type(2) | Reserved(2) | PNLen(2)
 * - Version (4 bytes)
 * - DCID Length (1 byte) + DCID
 * - SCID Length (1 byte) + SCID
 * - [Initial only: Token Length + Token]
 * - Payload Length (varint)
 * - Packet Number (protected)
 *
 * Short header format (1-RTT):
 * - First byte: Form(0) | Fixed(1) | Spin(1) | Reserved(2) | Key(1) | PNLen(2)
 * - DCID (known length from connection)
 * - Packet Number (protected)
 *
 * @param {Uint8Array} data - Packet data
 * @param {number} dcidLen - Known DCID length for short headers (default 8)
 * @returns {{pnOffset: number, packetType: string}|null}
 */
export function getQuicPnOffset(data, dcidLen = 8) {
    if (data.length < 5) return null;

    const isLong = (data[0] & 0x80) !== 0;

    if (isLong) {
        // Long header
        const packetType = (data[0] & 0x30) >> 4;
        const typeNames = ['Initial', '0-RTT', 'Handshake', 'Retry'];

        let offset = 1 + 4; // Skip first byte + version

        // DCID
        if (offset >= data.length) return null;
        const dcid = data[offset];
        offset += 1 + dcid;

        // SCID
        if (offset >= data.length) return null;
        const scid = data[offset];
        offset += 1 + scid;

        // Initial packets have token
        if (packetType === 0) {
            if (offset >= data.length) return null;
            const tokenLen = parseVarint(data, offset);
            if (!tokenLen) return null;
            offset += tokenLen.length + tokenLen.value;
        }

        // Payload length (varint)
        if (offset >= data.length) return null;
        const payloadLen = parseVarint(data, offset);
        if (!payloadLen) return null;
        offset += payloadLen.length;

        return { pnOffset: offset, packetType: typeNames[packetType] || 'Unknown' };
    } else {
        // Short header (1-RTT)
        // First byte + DCID
        const pnOffset = 1 + dcidLen;
        return { pnOffset, packetType: '1-RTT' };
    }
}

/**
 * Derive the next traffic secret for QUIC key update.
 * RFC 9001 Section 6.1: Key Update
 *
 * @param {Uint8Array} currentSecret - Current traffic secret
 * @returns {Promise<Uint8Array>}
 */
async function deriveNextTrafficSecret(currentSecret) {
    // Uses "tls13 quic traffic upd" label
    return await quicHkdfExpandLabel(currentSecret, 'traffic upd', new Uint8Array(0), 32);
}

/**
 * Main QUIC decryptor class.
 */
export class QuicDecryptor {
    constructor() {
        // Key phase 0 (initial)
        this.clientKeys0 = null;
        this.serverKeys0 = null;
        // Key phase 1 (after rotation)
        this.clientKeys1 = null;
        this.serverKeys1 = null;
        // 0-RTT keys
        this.earlyDataKeys = null;
        // Packet number tracking
        this.largestClientPn = -1;
        this.largestServerPn = -1;
        this.largestClient0RttPn = -1;  // Separate PN space for 0-RTT
    }

    /**
     * Initialize from parsed keylog data.
     *
     * @param {Object} keylog - Parsed keylog with traffic secrets
     */
    async initialize(keylog) {
        const keys = keylog.keys;

        if (keys.client_traffic_secret_0) {
            const clientSecret = hexToBytes(keys.client_traffic_secret_0);
            const serverSecret = hexToBytes(keys.server_traffic_secret_0);
            console.log('[QUIC] Deriving client/server keys (phase 0)');
            this.clientKeys0 = await deriveQuicKeys(clientSecret);
            this.serverKeys0 = await deriveQuicKeys(serverSecret);

            // Derive phase 1 keys for key rotation
            console.log('[QUIC] Deriving client/server keys (phase 1)');
            const clientSecret1 = await deriveNextTrafficSecret(clientSecret);
            const serverSecret1 = await deriveNextTrafficSecret(serverSecret);
            this.clientKeys1 = await deriveQuicKeys(clientSecret1);
            this.serverKeys1 = await deriveQuicKeys(serverSecret1);
        }

        if (keys.client_early_traffic_secret) {
            const earlySecret = hexToBytes(keys.client_early_traffic_secret);
            console.log('[QUIC] Deriving 0-RTT early data keys');
            this.earlyDataKeys = await deriveQuicKeys(earlySecret);
        }
    }

    /**
     * Try to decrypt a QUIC 1-RTT (short header) packet.
     * Tries all DCID lengths 0-20 and both key phases.
     *
     * @param {Uint8Array} data - Packet data
     * @param {boolean} isClient - True if from client
     * @returns {Promise<{plaintext: Uint8Array, packetNumber: number}|null>}
     */
    async tryDecrypt1Rtt(data, isClient) {
        const keys0 = isClient ? this.clientKeys0 : this.serverKeys0;
        const keys1 = isClient ? this.clientKeys1 : this.serverKeys1;
        const largestPn = isClient ? this.largestClientPn : this.largestServerPn;

        // Short header: first byte (1) + DCID (0-20 bytes) + packet number
        // Try all DCID lengths from 0 to 20
        for (let dcidLen = 0; dcidLen <= 20; dcidLen++) {
            const pnOffset = 1 + dcidLen;

            // Try phase 0 keys first (most common)
            if (keys0) {
                const result = await decryptQuicPacket(data, keys0, pnOffset, largestPn);
                if (result) {
                    console.log('[QUIC] Decrypted 1-RTT packet (phase 0, dcid=%d, pn=%d, len=%d)',
                        dcidLen, result.packetNumber, result.plaintext.length);
                    return result;
                }
            }

            // Try phase 1 keys (after key rotation)
            if (keys1) {
                const result = await decryptQuicPacket(data, keys1, pnOffset, largestPn);
                if (result) {
                    console.log('[QUIC] Decrypted 1-RTT packet (phase 1, dcid=%d, pn=%d, len=%d)',
                        dcidLen, result.packetNumber, result.plaintext.length);
                    return result;
                }
            }
        }

        return null;
    }

    /**
     * Try to decrypt a QUIC 0-RTT (long header) packet.
     *
     * @param {Uint8Array} data - Packet data
     * @returns {Promise<{plaintext: Uint8Array, packetNumber: number}|null>}
     */
    async tryDecrypt0Rtt(data) {
        if (!this.earlyDataKeys) return null;
        if (data.length < 20) return null;

        // Long header 0-RTT format:
        // First byte: 1 | 1 | 01 | Reserved | PNLen  (0xD* for 0-RTT)
        // Version (4 bytes)
        // DCID Length (1 byte) + DCID
        // SCID Length (1 byte) + SCID
        // Length (varint)
        // Packet Number (protected)

        let offset = 1;

        // Skip version (4 bytes)
        if (offset + 4 > data.length) return null;
        offset += 4;

        // DCID Length + DCID
        if (offset + 1 > data.length) return null;
        const dcidLen = data[offset];
        offset += 1 + dcidLen;

        // SCID Length + SCID
        if (offset >= data.length) return null;
        const scidLen = data[offset];
        offset += 1 + scidLen;

        // Payload Length (varint)
        if (offset >= data.length) return null;
        const lengthResult = parseVarint(data, offset);
        if (!lengthResult) return null;
        offset += lengthResult.length;

        // pnOffset is where the packet number starts
        const pnOffset = offset;

        const result = await decryptQuicPacket(data, this.earlyDataKeys, pnOffset, this.largestClient0RttPn);
        if (result) {
            this.largestClient0RttPn = Math.max(this.largestClient0RttPn, result.packetNumber);
            console.log('[QUIC] Decrypted 0-RTT packet (pn=%d, len=%d)',
                result.packetNumber, result.plaintext.length);
            return result;
        }

        return null;
    }

    /**
     * Try to decrypt a QUIC packet.
     *
     * @param {Uint8Array} data - Raw UDP payload (QUIC packet)
     * @param {string} direction - 'client' or 'server'
     * @returns {Promise<{plaintext: Uint8Array, packetType: string, packetNumber: number}|null>}
     */
    async tryDecrypt(data, direction) {
        if (data.length < 5) return null;

        const isClient = direction === 'client';
        const isLong = (data[0] & 0x80) !== 0;

        if (isLong) {
            // Long header packet
            const packetType = (data[0] & 0x30) >> 4;
            const typeNames = ['Initial', '0-RTT', 'Handshake', 'Retry'];
            const typeName = typeNames[packetType] || 'Unknown';

            console.log('[QUIC] Long header packet type: %s (0x%s)', typeName, packetType.toString(16));

            // Only handle 0-RTT packets from client
            if (packetType === 1 && isClient) {
                const result = await this.tryDecrypt0Rtt(data);
                if (result) {
                    return { ...result, packetType: '0-RTT' };
                }
            }

            // Skip Initial/Handshake packets (different keys)
            return null;
        } else {
            // Short header (1-RTT)
            // Check fixed bit (must be 1)
            if ((data[0] & 0x40) === 0) {
                console.log('[QUIC] Invalid fixed bit in short header');
                return null;
            }

            const result = await this.tryDecrypt1Rtt(data, isClient);
            if (result) {
                // Update largest PN
                if (isClient) {
                    this.largestClientPn = Math.max(this.largestClientPn, result.packetNumber);
                } else {
                    this.largestServerPn = Math.max(this.largestServerPn, result.packetNumber);
                }
                return { ...result, packetType: '1-RTT' };
            }
        }

        return null;
    }
}

/**
 * Parse QUIC frames from decrypted payload.
 *
 * @param {Uint8Array} payload - Decrypted QUIC payload
 * @returns {Array<{type: number, data: Uint8Array}>}
 */
export function parseQuicFrames(payload) {
    const frames = [];
    let offset = 0;

    while (offset < payload.length) {
        const frameType = parseVarint(payload, offset);
        if (!frameType) break;
        offset += frameType.length;

        // Handle different frame types
        const type = frameType.value;

        if (type === 0x00) {
            // PADDING - skip
            frames.push({ type, typeName: 'PADDING', data: new Uint8Array(0) });
        } else if (type === 0x01) {
            // PING
            frames.push({ type, typeName: 'PING', data: new Uint8Array(0) });
        } else if (type >= 0x02 && type <= 0x03) {
            // ACK
            // Parse ACK frame
            const largestAck = parseVarint(payload, offset);
            if (!largestAck) break;
            offset += largestAck.length;

            const ackDelay = parseVarint(payload, offset);
            if (!ackDelay) break;
            offset += ackDelay.length;

            const ackRangeCount = parseVarint(payload, offset);
            if (!ackRangeCount) break;
            offset += ackRangeCount.length;

            const firstAckRange = parseVarint(payload, offset);
            if (!firstAckRange) break;
            offset += firstAckRange.length;

            // Skip additional ACK ranges
            for (let i = 0; i < ackRangeCount.value; i++) {
                const gap = parseVarint(payload, offset);
                if (!gap) break;
                offset += gap.length;

                const ackRange = parseVarint(payload, offset);
                if (!ackRange) break;
                offset += ackRange.length;
            }

            // Skip ECN counts if type === 0x03
            if (type === 0x03) {
                for (let i = 0; i < 3; i++) {
                    const ecn = parseVarint(payload, offset);
                    if (!ecn) break;
                    offset += ecn.length;
                }
            }

            frames.push({ type, typeName: 'ACK', data: new Uint8Array(0) });
        } else if (type >= 0x04 && type <= 0x05) {
            // RESET_STREAM
            const streamId = parseVarint(payload, offset);
            if (!streamId) break;
            offset += streamId.length;

            const appError = parseVarint(payload, offset);
            if (!appError) break;
            offset += appError.length;

            const finalSize = parseVarint(payload, offset);
            if (!finalSize) break;
            offset += finalSize.length;

            frames.push({ type, typeName: 'RESET_STREAM', streamId: streamId.value, data: new Uint8Array(0) });
        } else if (type === 0x06) {
            // STOP_SENDING
            const streamId = parseVarint(payload, offset);
            if (!streamId) break;
            offset += streamId.length;

            const appError = parseVarint(payload, offset);
            if (!appError) break;
            offset += appError.length;

            frames.push({ type, typeName: 'STOP_SENDING', streamId: streamId.value, data: new Uint8Array(0) });
        } else if (type === 0x07) {
            // CRYPTO
            const cryptoOffset = parseVarint(payload, offset);
            if (!cryptoOffset) break;
            offset += cryptoOffset.length;

            const dataLen = parseVarint(payload, offset);
            if (!dataLen) break;
            offset += dataLen.length;

            if (offset + dataLen.value > payload.length) break;
            const data = payload.slice(offset, offset + dataLen.value);
            offset += dataLen.value;

            frames.push({ type, typeName: 'CRYPTO', data });
        } else if (type >= 0x08 && type <= 0x0f) {
            // STREAM frame
            const streamId = parseVarint(payload, offset);
            if (!streamId) break;
            offset += streamId.length;

            const hasOffset = (type & 0x04) !== 0;
            const hasLength = (type & 0x02) !== 0;
            const fin = (type & 0x01) !== 0;

            let streamOffset = 0;
            if (hasOffset) {
                const off = parseVarint(payload, offset);
                if (!off) break;
                streamOffset = off.value;
                offset += off.length;
            }

            let dataLen;
            if (hasLength) {
                const len = parseVarint(payload, offset);
                if (!len) break;
                dataLen = len.value;
                offset += len.length;
            } else {
                dataLen = payload.length - offset;
            }

            if (offset + dataLen > payload.length) break;
            const data = payload.slice(offset, offset + dataLen);
            offset += dataLen;

            frames.push({
                type,
                typeName: 'STREAM',
                streamId: streamId.value,
                offset: streamOffset,
                fin,
                data
            });
        } else if (type === 0x10) {
            // MAX_DATA
            const maxData = parseVarint(payload, offset);
            if (!maxData) break;
            offset += maxData.length;
            frames.push({ type, typeName: 'MAX_DATA', data: new Uint8Array(0) });
        } else if (type === 0x11) {
            // MAX_STREAM_DATA
            const streamId = parseVarint(payload, offset);
            if (!streamId) break;
            offset += streamId.length;

            const maxData = parseVarint(payload, offset);
            if (!maxData) break;
            offset += maxData.length;

            frames.push({ type, typeName: 'MAX_STREAM_DATA', streamId: streamId.value, data: new Uint8Array(0) });
        } else if (type >= 0x12 && type <= 0x13) {
            // MAX_STREAMS
            const maxStreams = parseVarint(payload, offset);
            if (!maxStreams) break;
            offset += maxStreams.length;
            frames.push({ type, typeName: 'MAX_STREAMS', data: new Uint8Array(0) });
        } else if (type === 0x14) {
            // DATA_BLOCKED
            const limit = parseVarint(payload, offset);
            if (!limit) break;
            offset += limit.length;
            frames.push({ type, typeName: 'DATA_BLOCKED', data: new Uint8Array(0) });
        } else if (type === 0x15) {
            // STREAM_DATA_BLOCKED
            const streamId = parseVarint(payload, offset);
            if (!streamId) break;
            offset += streamId.length;

            const limit = parseVarint(payload, offset);
            if (!limit) break;
            offset += limit.length;

            frames.push({ type, typeName: 'STREAM_DATA_BLOCKED', streamId: streamId.value, data: new Uint8Array(0) });
        } else if (type >= 0x16 && type <= 0x17) {
            // STREAMS_BLOCKED
            const limit = parseVarint(payload, offset);
            if (!limit) break;
            offset += limit.length;
            frames.push({ type, typeName: 'STREAMS_BLOCKED', data: new Uint8Array(0) });
        } else if (type === 0x18) {
            // NEW_CONNECTION_ID
            const seqNum = parseVarint(payload, offset);
            if (!seqNum) break;
            offset += seqNum.length;

            const retirePrior = parseVarint(payload, offset);
            if (!retirePrior) break;
            offset += retirePrior.length;

            if (offset >= payload.length) break;
            const connIdLen = payload[offset];
            offset += 1;

            if (offset + connIdLen + 16 > payload.length) break;
            offset += connIdLen + 16; // Skip Connection ID + Stateless Reset Token

            frames.push({ type, typeName: 'NEW_CONNECTION_ID', data: new Uint8Array(0) });
        } else if (type === 0x19) {
            // RETIRE_CONNECTION_ID
            const seqNum = parseVarint(payload, offset);
            if (!seqNum) break;
            offset += seqNum.length;
            frames.push({ type, typeName: 'RETIRE_CONNECTION_ID', data: new Uint8Array(0) });
        } else if (type === 0x1a) {
            // PATH_CHALLENGE
            if (offset + 8 > payload.length) break;
            offset += 8;
            frames.push({ type, typeName: 'PATH_CHALLENGE', data: new Uint8Array(0) });
        } else if (type === 0x1b) {
            // PATH_RESPONSE
            if (offset + 8 > payload.length) break;
            offset += 8;
            frames.push({ type, typeName: 'PATH_RESPONSE', data: new Uint8Array(0) });
        } else if (type >= 0x1c && type <= 0x1d) {
            // CONNECTION_CLOSE
            const errorCode = parseVarint(payload, offset);
            if (!errorCode) break;
            offset += errorCode.length;

            if (type === 0x1c) {
                // Application layer close - has frame type
                const frameTypeV = parseVarint(payload, offset);
                if (!frameTypeV) break;
                offset += frameTypeV.length;
            }

            const reasonLen = parseVarint(payload, offset);
            if (!reasonLen) break;
            offset += reasonLen.length;

            if (offset + reasonLen.value > payload.length) break;
            offset += reasonLen.value;

            frames.push({ type, typeName: 'CONNECTION_CLOSE', data: new Uint8Array(0) });
        } else if (type === 0x1e) {
            // HANDSHAKE_DONE
            frames.push({ type, typeName: 'HANDSHAKE_DONE', data: new Uint8Array(0) });
        } else {
            // Unknown frame type - try to skip or break
            console.warn('[QUIC] Unknown frame type 0x%s at offset %d', type.toString(16), offset);
            break;
        }
    }

    return frames;
}
