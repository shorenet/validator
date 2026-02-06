/**
 * QUIC decryption for HTTP/3 traffic.
 *
 * QUIC uses a different encryption scheme than TLS records:
 * - Header protection (AES-ECB mask)
 * - Packet number reconstruction
 * - Per-packet nonce (IV XOR packet number)
 */

import { hexToBytes } from './hash.js';
import { decodeVarint } from '../encoding/varint.js';
import { quicHkdfExpandLabel, deriveQuicKeys, deriveQuicInitialKeys } from './key-derivation.js';

// Re-export deriveQuicKeys for backward compatibility
export { deriveQuicKeys, deriveQuicInitialKeys };

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
    // Note: JavaScript bitwise shift wraps at 32 bits, so 1 << 32 === 1
    // Use Math.pow for correct behavior with larger bit widths
    const pnWin = Math.pow(2, pnBits);
    const pnHwin = Math.floor(pnWin / 2);

    // Use Math operations instead of bitwise for large numbers
    let candidatePn = (Math.floor(expectedPn / pnWin) * pnWin) + truncatedPn;

    if (candidatePn <= expectedPn - pnHwin && candidatePn < (1 << 62) - pnWin) {
        return candidatePn + pnWin;
    } else if (candidatePn > expectedPn + pnHwin && candidatePn >= pnWin) {
        return candidatePn - pnWin;
    }
    return candidatePn;
}

/**
 * Parse a QUIC variable-length integer (RFC 9000).
 * Wrapper around shared decodeVarint that maintains backward compatibility.
 *
 * @param {Uint8Array} data - Data buffer
 * @param {number} offset - Starting offset
 * @returns {{value: number, length: number}|null}
 */
export function parseVarint(data, offset) {
    try {
        const result = decodeVarint(data, offset);
        return { value: result.value, length: result.bytesRead };
    } catch (e) {
        // Shared module throws on error, but this wrapper returns null for backward compat
        return null;
    }
}

/**
 * Split coalesced QUIC packets in a UDP datagram.
 *
 * QUIC allows multiple packets to be coalesced in a single UDP datagram.
 * Long header packets have a Length field that allows splitting them.
 * Short header packets (1-RTT) must be last as they have no length field.
 *
 * @param {Uint8Array} payload - UDP payload containing QUIC packet(s)
 * @returns {Array<{data: Uint8Array, type: number|string}>} Array of packets with type
 */
export function splitCoalescedPackets(payload) {
    const packets = [];
    let offset = 0;

    while (offset < payload.length) {
        const firstByte = payload[offset];
        const isLongHeader = (firstByte & 0x80) !== 0;

        if (!isLongHeader) {
            // Short header (1-RTT) - rest of datagram is this packet
            packets.push({ data: payload.slice(offset), type: 'short' });
            break;
        }

        // Long header - parse to find Length field
        const packetType = (firstByte >> 4) & 0x03;
        let pos = offset + 1 + 4; // Skip first byte + version

        if (pos >= payload.length) break;
        const dcidLen = payload[pos];
        pos += 1 + dcidLen;

        if (pos >= payload.length) break;
        const scidLen = payload[pos];
        pos += 1 + scidLen;

        // Initial packets have token length + token
        if (packetType === 0) {
            const tokenLen = parseVarint(payload, pos);
            if (!tokenLen) break;
            pos += tokenLen.length + tokenLen.value;
        }

        // Read Length field (payload length including PN)
        const lengthField = parseVarint(payload, pos);
        if (!lengthField) break;
        pos += lengthField.length;

        const packetEnd = pos + lengthField.value;
        if (packetEnd > payload.length) {
            // Truncated packet - take rest
            packets.push({ data: payload.slice(offset), type: packetType });
            break;
        }

        packets.push({ data: payload.slice(offset, packetEnd), type: packetType });
        offset = packetEnd;
    }

    return packets;
}

/**
 * Decrypt a QUIC packet.
 *
 * @param {Uint8Array} data - Raw packet data
 * @param {{key: CryptoKey, keyBytes: Uint8Array, iv: Uint8Array, hpKey: CryptoKey, hpKeyBytes: Uint8Array}} keys - QUIC keys
 * @param {number} pnOffset - Packet number offset in header
 * @param {number} largestPn - Largest packet number seen
 * @param {number} payloadLength - Optional: exact payload length from QUIC Length field (for coalesced packets)
 * @returns {Promise<{plaintext: Uint8Array, packetNumber: number}|null>}
 */
async function decryptQuicPacket(data, keys, pnOffset, largestPn = 0, payloadLength = null) {
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

    // If payloadLength is provided (from QUIC Length field), use it to correctly
    // slice the ciphertext for coalesced packets. Otherwise, take all remaining bytes.
    // The Length field includes the packet number, so subtract pnLen.
    let ciphertext;
    if (payloadLength !== null) {
        const ciphertextLen = payloadLength - pnLen;
        if (payloadStart + ciphertextLen > dataCopy.length) {
            return null; // Not enough data
        }
        ciphertext = dataCopy.slice(payloadStart, payloadStart + ciphertextLen);
    } else {
        ciphertext = dataCopy.slice(payloadStart);
    }

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
        // Handshake keys (for decrypting Certificate messages)
        this.clientHandshakeKeys = null;
        this.serverHandshakeKeys = null;
        // Initial keys (for decrypting ClientHello/ServerHello)
        this.clientInitialKeys = null;
        this.serverInitialKeys = null;
        // 0-RTT keys
        this.earlyDataKeys = null;
        // Packet number tracking
        this.largestClientPn = -1;
        this.largestServerPn = -1;
        this.largestClient0RttPn = -1;  // Separate PN space for 0-RTT
        this.largestClientHandshakePn = -1;
        this.largestServerHandshakePn = -1;
        this.largestClientInitialPn = -1;
        this.largestServerInitialPn = -1;
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
            this.clientKeys0 = await deriveQuicKeys(clientSecret);
            this.serverKeys0 = await deriveQuicKeys(serverSecret);

            // Derive phase 1 keys for key rotation
            const clientSecret1 = await deriveNextTrafficSecret(clientSecret);
            const serverSecret1 = await deriveNextTrafficSecret(serverSecret);
            this.clientKeys1 = await deriveQuicKeys(clientSecret1);
            this.serverKeys1 = await deriveQuicKeys(serverSecret1);
        }

        if (keys.client_early_traffic_secret) {
            const earlySecret = hexToBytes(keys.client_early_traffic_secret);
            this.earlyDataKeys = await deriveQuicKeys(earlySecret);
        }

        // Derive handshake keys for certificate extraction
        if (keys.client_handshake_traffic_secret && keys.server_handshake_traffic_secret) {
            const clientHsSecret = hexToBytes(keys.client_handshake_traffic_secret);
            const serverHsSecret = hexToBytes(keys.server_handshake_traffic_secret);
            this.clientHandshakeKeys = await deriveQuicKeys(clientHsSecret);
            this.serverHandshakeKeys = await deriveQuicKeys(serverHsSecret);
        }
    }

    /**
     * Initialize Initial keys from DCID extracted from first client packet.
     *
     * @param {Uint8Array} dcid - Destination Connection ID
     */
    async initializeInitialKeys(dcid) {
        const { clientKeys, serverKeys } = await deriveQuicInitialKeys(dcid);
        this.clientInitialKeys = clientKeys;
        this.serverInitialKeys = serverKeys;
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
                    return result;
                }
            }

            // Try phase 1 keys (after key rotation)
            if (keys1) {
                const result = await decryptQuicPacket(data, keys1, pnOffset, largestPn);
                if (result) {
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

        // Pass the exact payload length to avoid including coalesced packets in ciphertext
        const result = await decryptQuicPacket(data, this.earlyDataKeys, pnOffset, this.largestClient0RttPn, lengthResult.value);
        if (result) {
            this.largestClient0RttPn = Math.max(this.largestClient0RttPn, result.packetNumber);
            return result;
        }

        return null;
    }

    /**
     * Try to decrypt a QUIC Initial packet.
     *
     * @param {Uint8Array} data - Raw long header packet (may be coalesced with other packets)
     * @param {boolean} isClient - True if from client
     * @returns {Promise<{plaintext: Uint8Array, packetNumber: number}|null>}
     */
    async tryDecryptInitial(data, isClient) {
        const keys = isClient ? this.clientInitialKeys : this.serverInitialKeys;
        if (!keys) return null;

        const largestPn = isClient ? this.largestClientInitialPn : this.largestServerInitialPn;

        // Initial packet format:
        // First byte: 1 | 1 | 00 | Reserved | PNLen
        // Version (4 bytes)
        // DCID Length (1 byte) + DCID
        // SCID Length (1 byte) + SCID
        // Token Length (varint) + Token
        // Length (varint)
        // Packet Number (protected)

        let offset = 1 + 4; // Skip form/type byte and version
        if (offset >= data.length) return null;

        const dcidLen = data[offset];
        offset += 1 + dcidLen;
        if (offset >= data.length) return null;

        const scidLen = data[offset];
        offset += 1 + scidLen;
        if (offset >= data.length) return null;

        // Token Length (varint) + Token
        const tokenLen = parseVarint(data, offset);
        if (!tokenLen) return null;
        offset += tokenLen.length + tokenLen.value;
        if (offset >= data.length) return null;

        // Payload length (varint) - exact length for this packet (for coalesced packets)
        const payloadLen = parseVarint(data, offset);
        if (!payloadLen) return null;
        offset += payloadLen.length;

        // Packet number starts here
        const pnOffset = offset;

        // Pass the exact payload length to avoid including coalesced packets in ciphertext
        const result = await decryptQuicPacket(data, keys, pnOffset, largestPn, payloadLen.value);
        if (result) {
            // Update largest PN
            if (isClient) {
                this.largestClientInitialPn = Math.max(this.largestClientInitialPn, result.packetNumber);
            } else {
                this.largestServerInitialPn = Math.max(this.largestServerInitialPn, result.packetNumber);
            }
            return result;
        }

        return null;
    }

    /**
     * Try to decrypt a QUIC Handshake packet.
     *
     * @param {Uint8Array} data - Raw long header packet (may be coalesced with other packets)
     * @param {boolean} isClient - True if from client
     * @returns {Promise<{plaintext: Uint8Array, packetNumber: number}|null>}
     */
    async tryDecryptHandshake(data, isClient) {
        const keys = isClient ? this.clientHandshakeKeys : this.serverHandshakeKeys;
        if (!keys) return null;

        const largestPn = isClient ? this.largestClientHandshakePn : this.largestServerHandshakePn;

        // Long header: first byte, version (4), DCID len (1) + DCID, SCID len (1) + SCID, payload len, PN
        let offset = 1 + 4; // Skip form/type byte and version
        if (offset >= data.length) return null;

        const dcidLen = data[offset];
        offset += 1 + dcidLen;
        if (offset >= data.length) return null;

        const scidLen = data[offset];
        offset += 1 + scidLen;
        if (offset >= data.length) return null;

        // Payload length (varint) - this is the exact length of this packet's payload
        // Critical for coalesced packets: don't include trailing packets in decryption
        const payloadLen = parseVarint(data, offset);
        if (!payloadLen) return null;
        offset += payloadLen.length;

        // Packet number starts here
        const pnOffset = offset;

        // Pass the exact payload length to avoid including coalesced packets in ciphertext
        const result = await decryptQuicPacket(data, keys, pnOffset, largestPn, payloadLen.value);
        if (result) {
            // Update largest PN
            if (isClient) {
                this.largestClientHandshakePn = Math.max(this.largestClientHandshakePn, result.packetNumber);
            } else {
                this.largestServerHandshakePn = Math.max(this.largestServerHandshakePn, result.packetNumber);
            }
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

            // Handle 0-RTT packets from client
            if (packetType === 1 && isClient) {
                const result = await this.tryDecrypt0Rtt(data);
                if (result) {
                    return { ...result, packetType: '0-RTT' };
                }
            }

            // Handle Handshake packets (type 2)
            if (packetType === 2) {
                const result = await this.tryDecryptHandshake(data, isClient);
                if (result) {
                    return { ...result, packetType: 'Handshake' };
                }
            }

            // Handle Initial packets (type 0)
            if (packetType === 0) {
                const result = await this.tryDecryptInitial(data, isClient);
                if (result) {
                    return { ...result, packetType: 'Initial' };
                }
            }

            // Skip Retry packets (type 3)
            return null;
        } else {
            // Short header (1-RTT)
            // Check fixed bit (must be 1)
            if ((data[0] & 0x40) === 0) {
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
 * Extract DCID from a QUIC Initial packet (first byte is long header with type 0).
 *
 * @param {Uint8Array} data - Raw packet data
 * @returns {Uint8Array|null} - DCID or null if not an Initial packet
 */
export function extractDcidFromInitial(data) {
    if (data.length < 10) return null;

    // Check for long header
    if ((data[0] & 0x80) === 0) return null;

    // Check for Initial packet (type 0)
    const packetType = (data[0] & 0x30) >> 4;
    if (packetType !== 0) return null;

    // Skip first byte + version (4 bytes)
    let offset = 1 + 4;
    if (offset >= data.length) return null;

    // DCID Length + DCID
    const dcidLen = data[offset];
    if (offset + 1 + dcidLen > data.length) return null;

    return data.slice(offset + 1, offset + 1 + dcidLen);
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
        } else if (type === 0x04) {
            // RESET_STREAM (RFC 9000: type 0x04)
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
        } else if (type === 0x05) {
            // STOP_SENDING (RFC 9000: type 0x05)
            const streamId = parseVarint(payload, offset);
            if (!streamId) break;
            offset += streamId.length;

            const appError = parseVarint(payload, offset);
            if (!appError) break;
            offset += appError.length;

            frames.push({ type, typeName: 'STOP_SENDING', streamId: streamId.value, data: new Uint8Array(0) });
        } else if (type === 0x06) {
            // CRYPTO (RFC 9000: type 0x06)
            const cryptoOffset = parseVarint(payload, offset);
            if (!cryptoOffset) break;
            offset += cryptoOffset.length;

            const dataLen = parseVarint(payload, offset);
            if (!dataLen) break;
            offset += dataLen.length;

            if (offset + dataLen.value > payload.length) break;
            const data = payload.slice(offset, offset + dataLen.value);
            offset += dataLen.value;

            frames.push({ type, typeName: 'CRYPTO', offset: cryptoOffset.value, data });
        } else if (type === 0x07) {
            // NEW_TOKEN (RFC 9000: type 0x07)
            const tokenLen = parseVarint(payload, offset);
            if (!tokenLen) break;
            offset += tokenLen.length;

            if (offset + tokenLen.value > payload.length) break;
            offset += tokenLen.value;

            frames.push({ type, typeName: 'NEW_TOKEN', data: new Uint8Array(0) });
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
            break;
        }
    }

    return frames;
}
