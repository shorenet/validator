/**
 * TLS 1.2 and TLS 1.3 decryption using Web Crypto API.
 * Handles session tickets and resumption.
 */

import { hexToBytes, bytesToHex, base64ToBytes } from './hash.js';
import { hkdfExpandLabel, deriveTrafficKeys, tls12Prf } from './key-derivation.js';
import { parseRecords, TLS_CONTENT_TYPE, TLS_HANDSHAKE_TYPE } from '../protocol/tls/record-parser.js';

// Re-export for backward compatibility
export { parseRecords as parseTlsRecords, TLS_CONTENT_TYPE, TLS_HANDSHAKE_TYPE };

/**
 * XOR the IV with the sequence number to get the nonce.
 * @param {Uint8Array} iv - 12-byte IV
 * @param {bigint|number} seqNum - Sequence number
 * @returns {Uint8Array} 12-byte nonce
 */
function computeNonce(iv, seqNum) {
    const nonce = new Uint8Array(iv);
    const seqBytes = new Uint8Array(8);
    let seq = BigInt(seqNum);

    // Write sequence number as big-endian 64-bit
    for (let i = 7; i >= 0; i--) {
        seqBytes[i] = Number(seq & 0xffn);
        seq >>= 8n;
    }

    // XOR with the last 8 bytes of the IV
    for (let i = 0; i < 8; i++) {
        nonce[i + 4] ^= seqBytes[i];
    }

    return nonce;
}

/**
 * Decrypt a TLS 1.3 record.
 * @param {Uint8Array} ciphertext - The encrypted record (including content type byte and tag)
 * @param {CryptoKey} key - AES-GCM key
 * @param {Uint8Array} iv - Base IV
 * @param {number} seqNum - Sequence number
 * @param {Uint8Array} recordHeader - The actual 5-byte TLS record header from the wire
 * @returns {Promise<{plaintext: Uint8Array, contentType: number}>}
 */
async function decryptTls13Record(ciphertext, key, iv, seqNum, recordHeader) {
    const nonce = computeNonce(iv, seqNum);

    // Additional authenticated data: use the actual record header from the wire
    // NOT a constructed header! Python does this correctly at line 571
    const aad = recordHeader;

    try {
        const plaintext = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: nonce,
                additionalData: aad,
                tagLength: 128
            },
            key,
            ciphertext
        );

        const ptBytes = new Uint8Array(plaintext);

        // Remove padding and get content type (last non-zero byte)
        let contentType = 0;
        let endIndex = ptBytes.length;
        for (let i = ptBytes.length - 1; i >= 0; i--) {
            if (ptBytes[i] !== 0) {
                contentType = ptBytes[i];
                endIndex = i;
                break;
            }
        }

        return {
            plaintext: ptBytes.slice(0, endIndex),
            contentType
        };
    } catch (e) {
        throw new Error(`TLS 1.3 decryption failed: ${e.message}`);
    }
}

/**
 * Derive TLS 1.2 key material from master secret.
 * key_block = PRF(master_secret, "key expansion", server_random + client_random)
 *
 * @param {Uint8Array} masterSecret - 48-byte master secret
 * @param {Uint8Array} clientRandom - 32-byte client random
 * @param {Uint8Array} serverRandom - 32-byte server random
 * @param {Object} cipherSuite - Cipher suite parameters
 * @returns {Promise<{clientKey: CryptoKey, serverKey: CryptoKey, clientIv: Uint8Array, serverIv: Uint8Array}>}
 */
async function deriveTls12Keys(masterSecret, clientRandom, serverRandom, cipherSuite) {
    const seed = new Uint8Array(64);
    seed.set(serverRandom);
    seed.set(clientRandom, 32);

    // Key block layout for AES-GCM:
    // client_write_key (16 or 32 bytes)
    // server_write_key (16 or 32 bytes)
    // client_write_IV (4 bytes - implicit)
    // server_write_IV (4 bytes - implicit)
    const keyLen = cipherSuite.keyLength || 16;
    const ivLen = 4; // Implicit IV for GCM

    const keyBlockLen = keyLen * 2 + ivLen * 2;
    const keyBlock = await tls12Prf(masterSecret, 'key expansion', seed, keyBlockLen);

    let offset = 0;
    const clientKeyBytes = keyBlock.slice(offset, offset + keyLen);
    offset += keyLen;
    const serverKeyBytes = keyBlock.slice(offset, offset + keyLen);
    offset += keyLen;
    const clientIv = keyBlock.slice(offset, offset + ivLen);
    offset += ivLen;
    const serverIv = keyBlock.slice(offset, offset + ivLen);

    const clientKey = await crypto.subtle.importKey(
        'raw',
        clientKeyBytes,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );

    const serverKey = await crypto.subtle.importKey(
        'raw',
        serverKeyBytes,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );

    return { clientKey, serverKey, clientIv, serverIv };
}

/**
 * Decrypt a TLS 1.2 GCM record.
 * @param {Uint8Array} ciphertext - The encrypted data (includes explicit nonce + ciphertext + tag)
 * @param {CryptoKey} key - AES-GCM key
 * @param {Uint8Array} implicitIv - 4-byte implicit IV
 * @param {Uint8Array} recordHeader - 5-byte TLS record header (for AAD)
 * @param {bigint|number} seqNum - Sequence number for AAD
 * @returns {Promise<Uint8Array>}
 */
async function decryptTls12GcmRecord(ciphertext, key, implicitIv, recordHeader, seqNum) {
    // First 8 bytes are explicit nonce
    const explicitNonce = ciphertext.slice(0, 8);
    const encryptedData = ciphertext.slice(8);

    // Full nonce = implicit IV (4 bytes) || explicit nonce (8 bytes)
    const nonce = new Uint8Array(12);
    nonce.set(implicitIv);
    nonce.set(explicitNonce, 4);

    // AAD = seq_num (8 bytes) || content_type (1) || version (2) || plaintext_length (2)
    const plaintextLength = encryptedData.length - 16; // Subtract auth tag
    const aad = new Uint8Array(13);

    // Write sequence number as big-endian 64-bit
    let seq = BigInt(seqNum);
    for (let i = 7; i >= 0; i--) {
        aad[i] = Number(seq & 0xffn);
        seq >>= 8n;
    }

    // Add record header components
    aad[8] = recordHeader[0];  // content type
    aad[9] = recordHeader[1];  // version high byte
    aad[10] = recordHeader[2]; // version low byte
    aad[11] = (plaintextLength >> 8) & 0xff; // length high byte
    aad[12] = plaintextLength & 0xff;        // length low byte

    try {
        const plaintext = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: nonce,
                additionalData: aad,
                tagLength: 128
            },
            key,
            encryptedData
        );

        return new Uint8Array(plaintext);
    } catch (e) {
        throw new Error(`TLS 1.2 GCM decryption failed: ${e.message}`);
    }
}

/**
 * Main TLS decryption class for forensic evidence validation.
 */
export class TlsDecryptor {
    constructor() {
        this.version = null;
        this.clientKey = null;
        this.serverKey = null;
        this.clientIv = null;
        this.serverIv = null;
        // TLS 1.3: separate sequence counters for handshake and application traffic
        this.clientHandshakeSeq = 0n;
        this.serverHandshakeSeq = 0n;
        this.clientAppSeq = 0n;
        this.serverAppSeq = 0n;
        // TLS 1.2: single sequence counter
        this.clientSeq = 0n;
        this.serverSeq = 0n;
    }

    /**
     * Initialize from keylog entries.
     * @param {Object} keylog - Keylog data from forensic evidence
     * @param {string} keylog.version - TLS version (TLS12 or TLS13)
     * @param {string} keylog.client_random - Client random in hex
     * @param {Object} keylog.keys - Key material
     */
    async initialize(keylog) {
        this.version = keylog.version;

        if (keylog.version === 'TLS13') {
            await this.initTls13(keylog);
        } else if (keylog.version === 'TLS12') {
            await this.initTls12(keylog);
        } else {
            throw new Error(`Unsupported TLS version: ${keylog.version}`);
        }
    }

    async initTls13(keylog) {
        const keys = keylog.keys;

        // TLS 1.3 uses traffic secrets directly
        if (keys.client_handshake_traffic_secret) {
            // Handshake keys (for encrypted handshake messages)
            const chts = hexToBytes(keys.client_handshake_traffic_secret);
            const shts = hexToBytes(keys.server_handshake_traffic_secret);
            this.handshakeClientKeys = await deriveTrafficKeys(chts);
            this.handshakeServerKeys = await deriveTrafficKeys(shts);
        }

        if (keys.client_traffic_secret_0) {
            // Application traffic keys
            const cts = hexToBytes(keys.client_traffic_secret_0);
            const sts = hexToBytes(keys.server_traffic_secret_0);
            const clientKeys = await deriveTrafficKeys(cts);
            const serverKeys = await deriveTrafficKeys(sts);

            this.clientKey = clientKeys.key;
            this.clientIv = clientKeys.iv;
            this.serverKey = serverKeys.key;
            this.serverIv = serverKeys.iv;
        }

        // Handle session resumption with session tickets
        if (keys.resumption_master_secret) {
            this.resumptionMasterSecret = hexToBytes(keys.resumption_master_secret);
        }
    }

    async initTls12(keylog) {
        const keys = keylog.keys;

        if (keys.master_secret) {
            const masterSecret = hexToBytes(keys.master_secret);
            const clientRandom = hexToBytes(keylog.client_random);
            const serverRandom = hexToBytes(keys.server_random || keylog.server_random);

            const cipherSuite = {
                keyLength: 16 // AES-128
            };

            const derived = await deriveTls12Keys(masterSecret, clientRandom, serverRandom, cipherSuite);
            this.clientKey = derived.clientKey;
            this.serverKey = derived.serverKey;
            this.clientIv = derived.clientIv;
            this.serverIv = derived.serverIv;
        }
    }

    /**
     * Decrypt a TLS record using exact sequence number and key type (if available) or search.
     * @param {Uint8Array} record - Full TLS record including header
     * @param {string} direction - 'client' or 'server'
     * @param {number} hintSeq - Sequence number to try first (default: 0)
     * @param {number|null} tlsRecordSeq - Exact TLS record sequence from forensic evidence (if available)
     * @param {string|null} tlsKeyType - Key type hint: 'handshake' or 'application' (if available)
     * @returns {Promise<{plaintext: Uint8Array, contentType: number, seq: number, keyType: string}>}
     */
    async decryptRecord(record, direction, hintSeq = 0, tlsRecordSeq = null, tlsKeyType = null) {
        const contentType = record[0];
        const recordVersion = (record[1] << 8) | record[2];
        const length = (record[3] << 8) | record[4];
        const ciphertext = record.slice(5, 5 + length);

        const isClient = direction === 'client';

        if (this.version === 'TLS13') {
            // Use exact sequence number from hintSeq (modern behavior)
            // The hint is authoritative - TLS sequence numbers must be strictly incrementing
            // Fallback to search only if hintSeq is explicitly 0 and tlsRecordSeq not provided
            // (for backward compatibility with old forensic evidence)
            const useSearch = hintSeq === 0 && (tlsRecordSeq === null || tlsRecordSeq === undefined);
            const seqsToTry = (tlsRecordSeq !== null && tlsRecordSeq !== undefined)
                ? [tlsRecordSeq]  // Forensic evidence provides exact seq
                : useSearch
                    ? (() => {
                        // Legacy search mode (only for first record)
                        const seqs = [];
                        for (let i = 0; i < 1000; i++) {
                            seqs.push(i);
                        }
                        return seqs;
                    })()
                    : [hintSeq];  // Use hint as exact sequence (no search)

            // Build key list - prefer specific key type if hint available
            const keysToTry = [];

            // Application traffic keys
            const appKey = isClient ? this.clientKey : this.serverKey;
            const appIv = isClient ? this.clientIv : this.serverIv;

            // Handshake traffic keys
            const handshakeKeys = isClient ? this.handshakeClientKeys : this.handshakeServerKeys;

            // If key type hint is provided, try that first (or only that if exact seq provided)
            if (tlsKeyType === 'application' && appKey && appIv) {
                keysToTry.push({ key: appKey, iv: appIv, type: 'application' });
                // Only try other keys if we don't have exact sequence
                if (tlsRecordSeq === null && handshakeKeys) {
                    keysToTry.push({ key: handshakeKeys.key, iv: handshakeKeys.iv, type: 'handshake' });
                }
            } else if (tlsKeyType === 'handshake' && handshakeKeys) {
                keysToTry.push({ key: handshakeKeys.key, iv: handshakeKeys.iv, type: 'handshake' });
                // Only try other keys if we don't have exact sequence
                if (tlsRecordSeq === null && appKey && appIv) {
                    keysToTry.push({ key: appKey, iv: appIv, type: 'application' });
                }
            } else {
                // No key type hint - try both (application first, then handshake)
                if (appKey && appIv) {
                    keysToTry.push({ key: appKey, iv: appIv, type: 'application' });
                }
                if (handshakeKeys) {
                    keysToTry.push({ key: handshakeKeys.key, iv: handshakeKeys.iv, type: 'handshake' });
                }
            }

            // Extract the actual record header (first 5 bytes) to use as AAD
            const recordHeader = record.slice(0, 5);

            // Try each key with each sequence
            for (const { key, iv, type } of keysToTry) {
                for (const seq of seqsToTry) {
                    try {
                        const result = await decryptTls13Record(ciphertext, key, iv, BigInt(seq), recordHeader);
                        return { plaintext: result.plaintext, contentType: result.contentType, seq, keyType: type };
                    } catch (e) {
                        // Try next sequence/key combo
                        continue;
                    }
                }
            }

            throw new Error(`Failed to decrypt TLS 1.3 record with any key/sequence`);
        } else {
            // TLS 1.2 decryption with exact sequence or search
            const key = isClient ? this.clientKey : this.serverKey;
            const implicitIv = isClient ? this.clientIv : this.serverIv;
            const header = record.slice(0, 5);

            // Use exact sequence number from hintSeq (modern behavior)
            // The hint is authoritative - TLS sequence numbers must be strictly incrementing
            // Fallback to search only if hintSeq is explicitly 0 and tlsRecordSeq not provided
            const useSearch = hintSeq === 0 && (tlsRecordSeq === null || tlsRecordSeq === undefined);
            const seqsToTry = (tlsRecordSeq !== null && tlsRecordSeq !== undefined)
                ? [tlsRecordSeq]  // Forensic evidence provides exact seq
                : useSearch
                    ? (() => {
                        // Legacy search mode (only for first record)
                        const seqs = [];
                        for (let i = 0; i < 1000; i++) {
                            seqs.push(i);
                        }
                        return seqs;
                    })()
                    : [hintSeq];  // Use hint as exact sequence (no search)

            for (const seq of seqsToTry) {
                try {
                    const plaintext = await decryptTls12GcmRecord(ciphertext, key, implicitIv, header, seq);
                    return { plaintext, contentType, seq, keyType: 'application' };
                } catch (e) {
                    // Try next sequence
                    continue;
                }
            }

            throw new Error(`Failed to decrypt TLS 1.2 record with any sequence`);
        }
    }

    /**
     * Reset sequence numbers (for key updates in TLS 1.3).
     */
    resetSequenceNumbers() {
        this.clientSeq = 0n;
        this.serverSeq = 0n;
    }
}
