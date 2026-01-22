#!/usr/bin/env node
/**
 * Batch validator for Harbour transactions
 * Validates forensic evidence from JSONL files
 */

import { createReadStream } from 'fs';
import { createInterface } from 'readline';
import { webcrypto } from 'crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { base64ToBytes } from './js/crypto/hash.js';
import { TlsDecryptor, parseTlsRecords, TLS_CONTENT_TYPE } from './js/crypto/tls.js';
import { QuicDecryptor } from './js/crypto/quic.js';
import { parseFrames, FrameType, extractHeaderBlock } from './js/protocol/http2.js';
import { HpackDecoder } from './js/protocol/hpack.js';

const inputFile = process.argv[2] || '/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl';

// Suppress verbose TLS logging
const originalLog = console.log;
console.log = (...args) => {
    if (typeof args[0] === 'string' && args[0].startsWith('[TLS]')) return;
    originalLog(...args);
};

/**
 * Parse keylog string into structured object for TlsDecryptor.
 * Keylog format: "LABEL client_random hex_secret\n..."
 */
function parseKeylog(keylogStr) {
    if (!keylogStr) return null;
    if (typeof keylogStr === 'object') return keylogStr; // Already parsed

    const keys = {};
    let clientRandom = null;
    const lines = keylogStr.split('\n');

    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;

        const parts = trimmed.split(/\s+/);
        if (parts.length < 3) continue;

        const label = parts[0].toLowerCase();

        // Handle TLS 1.2 CLIENT_RANDOM format: CLIENT_RANDOM <client_random> <master_secret>
        if (label === 'client_random' && parts.length === 3) {
            clientRandom = parts[1]; // Store at top level for TLS 1.2
            keys.master_secret = parts[2];
        } else {
            // TLS 1.3 format: LABEL <client_random> <secret>
            const secret = parts[2];
            keys[label] = secret;
        }
    }

    // Detect TLS version from keys present
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

    // For TLS 1.2, store client_random at top level (required by initTls12)
    if (version === 'TLS12') {
        result.client_random = clientRandom;
    }

    return result;
}


/**
 * Extract TLS payload from raw packet data (handles Ethernet, IPv4, IPv6)
 */
function extractTlsPayload(data) {
    if (!data || data.length < 5) return null;

    // Check if it's already TLS record layer data
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
            // Ethernet + IPv4
            return extractFromIpv4(data.slice(14));
        } else if (etherType === 0x86DD) {
            // Ethernet + IPv6
            return extractFromIpv6(data.slice(14));
        }
    }

    return null;
}

function extractFromIpv4(data) {
    if (data.length < 20) return null;
    const ihl = (data[0] & 0x0f) * 4;
    const protocol = data[9];

    // Support both TCP (6) and UDP (17) for HTTP/3
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
        const payload = data.slice(udpStart + 8); // UDP header is 8 bytes
        return payload.length > 0 ? payload : null;
    }

    return null;
}

function extractFromIpv6(data) {
    if (data.length < 40) return null;
    const nextHeader = data[6];

    // Support both TCP (6) and UDP (17) for HTTP/3
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
 * Validate an HTTP/3 (QUIC) transaction
 */
async function validateQuicTransaction(tx, result, keylog, packets) {
    console.log(`\n[TX ${tx.id}] HTTP/3 QUIC decryption`);

    // Initialize QUIC decryptor
    const decryptor = new QuicDecryptor();
    await decryptor.initialize(keylog);

    console.log(`  Total packets: ${packets.length}`);

    let decryptedPackets = 0;
    let totalBytes = 0;

    // Try to decrypt each packet
    for (const pkt of packets) {
        if (pkt.packet_type !== 'application') continue;

        const rawData = base64ToBytes(pkt.data);
        const udpPayload = extractTlsPayload(rawData);

        if (!udpPayload || udpPayload.length === 0) continue;

        const isClient = pkt.direction === 'client_to_server';

        try {
            // Try 1-RTT decryption
            const decrypted = await decryptor.tryDecrypt1Rtt(udpPayload, isClient);
            if (decrypted) {
                decryptedPackets++;
                totalBytes += decrypted.plaintext.length;
                // Update largest PN
                if (isClient) {
                    decryptor.largestClientPn = Math.max(decryptor.largestClientPn, decrypted.packetNumber);
                } else {
                    decryptor.largestServerPn = Math.max(decryptor.largestServerPn, decrypted.packetNumber);
                }
            }
        } catch (e) {
            // Decryption failed, continue
        }
    }

    console.log(`  Decrypted ${decryptedPackets} QUIC packets, ${totalBytes} bytes`);

    if (decryptedPackets > 0) {
        result.valid = true;
        result.level = 'decrypt';
    } else {
        result.error = 'Failed to decrypt any QUIC packets';
    }

    return result;
}

function hexToBytes(hex) {
    if (!hex) return null;
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

/**
 * Extract server_random from ServerHello in handshake packets (for TLS 1.2)
 * Returns 32-byte server_random or null if not found
 */
function extractServerRandom(packets) {
    for (const pkt of packets) {
        if (pkt.packet_type !== 'handshake') continue;
        if (pkt.direction !== 'server_to_client') continue; // ServerHello comes from server

        const rawData = base64ToBytes(pkt.data);
        const tcpPayload = extractTlsPayload(rawData);

        if (!tcpPayload || tcpPayload.length === 0) continue;

        // Look for TLS handshake records
        let offset = 0;
        while (offset + 5 <= tcpPayload.length) {
            const contentType = tcpPayload[offset];
            const recordLen = (tcpPayload[offset + 3] << 8) | tcpPayload[offset + 4];

            if (contentType !== 22) {  // Not handshake record
                offset += 5 + recordLen;
                continue;
            }

            // Check if this record is long enough for a ServerHello
            if (offset + 5 + 38 > tcpPayload.length) {
                offset += 5 + recordLen;
                continue;
            }

            const hsType = tcpPayload[offset + 5]; // First byte after TLS record header
            if (hsType === 0x02) {  // ServerHello
                // ServerHello structure (inside TLS record):
                // - handshake type (1 byte) = 0x02
                // - length (3 bytes)
                // - protocol version (2 bytes)
                // - random (32 bytes) <- what we want
                const randomOffset = offset + 5 + 1 + 3 + 2;
                if (randomOffset + 32 <= tcpPayload.length) {
                    return tcpPayload.slice(randomOffset, randomOffset + 32);
                }
            }

            offset += 5 + recordLen;
        }
    }
    return null;
}

/**
 * Validate a WebSocket message
 * WebSockets use the same TLS encryption as HTTP/1.1 - we can decrypt and verify payload
 */
async function validateWebSocketMessage(tx) {
    const result = {
        id: tx.id,
        protocol: 'WebSocket',
        url: tx.url,
        valid: false,
        level: 'none',
        error: null
    };

    const evidence = tx.forensic_evidence;
    if (!evidence) {
        result.error = 'No forensic evidence';
        return result;
    }

    const keylogRaw = evidence.keylog;
    const allPackets = evidence.raw_packets?.packets || [];

    if (!keylogRaw) {
        result.error = 'No keylog';
        return result;
    }

    if (allPackets.length === 0) {
        result.error = 'No packets';
        return result;
    }

    const keylog = parseKeylog(keylogRaw);
    if (!keylog) {
        result.error = 'Failed to parse keylog';
        return result;
    }

    // For TLS 1.2, extract server_random from ServerHello
    if (keylog.version === 'TLS12' && !keylog.keys.server_random) {
        const serverRandom = extractServerRandom(allPackets);
        if (serverRandom) {
            keylog.server_random = Array.from(serverRandom)
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        } else {
            result.error = 'TLS 1.2: server_random not found in ServerHello';
            return result;
        }
    }

    try {
        // Initialize TLS decryptor (same as HTTP/1.1)
        const decryptor = new TlsDecryptor();
        await decryptor.initialize(keylog);

        console.log(`\n[TX ${tx.id}] WebSocket decryption`);
        console.log(`  URL: ${tx.url}`);
        console.log(`  Message type: ${tx.message_type}`);
        console.log(`  Direction: ${tx.direction}`);

        // Extract TLS payloads and separate by direction
        const clientPayloads = [];
        const serverPayloads = [];

        for (const packet of allPackets) {
            const rawData = base64ToBytes(packet.data);
            const tlsData = extractTlsPayload(rawData);
            if (!tlsData || tlsData.length === 0) continue;

            if (packet.direction === 'client_to_server') {
                clientPayloads.push(tlsData);
            } else {
                serverPayloads.push(tlsData);
            }
        }

        // Concatenate into continuous streams
        const concatenate = (arrays) => {
            const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
            const buf = new Uint8Array(totalLength);
            let offset = 0;
            for (const arr of arrays) {
                buf.set(arr, offset);
                offset += arr.length;
            }
            return buf;
        };

        const clientStream = clientPayloads.length > 0 ? concatenate(clientPayloads) : new Uint8Array(0);
        const serverStream = serverPayloads.length > 0 ? concatenate(serverPayloads) : new Uint8Array(0);

        console.log(`  Client stream: ${clientStream.length} bytes`);
        console.log(`  Server stream: ${serverStream.length} bytes`);

        // Parse TLS records and decrypt
        let decryptedRecords = 0;
        let totalDecryptedBytes = 0;

        // Process client stream
        const clientRecords = parseTlsRecords(clientStream);
        let clientSeq = 0;
        for (const record of clientRecords) {
            if (record.type === 23) { // APPLICATION_DATA
                try {
                    const decrypted = await decryptor.decryptRecord(record.raw, 'client', clientSeq);
                    if (decrypted && decrypted.plaintext) {
                        decryptedRecords++;
                        totalDecryptedBytes += decrypted.plaintext.length;
                        clientSeq = decrypted.seq + 1;
                    }
                } catch (e) {
                    // Continue to next record
                }
            }
        }

        // Process server stream
        const serverRecords = parseTlsRecords(serverStream);
        let serverSeq = 0;
        for (const record of serverRecords) {
            if (record.type === 23) { // APPLICATION_DATA
                try {
                    const decrypted = await decryptor.decryptRecord(record.raw, 'server', serverSeq);
                    if (decrypted && decrypted.plaintext) {
                        decryptedRecords++;
                        totalDecryptedBytes += decrypted.plaintext.length;
                        serverSeq = decrypted.seq + 1;
                    }
                } catch (e) {
                    // Continue to next record
                }
            }
        }

        console.log(`  RESULT: Decrypted ${decryptedRecords} records, ${totalDecryptedBytes} bytes`);

        if (decryptedRecords > 0) {
            result.valid = true;
            result.level = 'decrypt';
        } else {
            result.error = 'Failed to decrypt any WebSocket TLS records';
        }

        return result;
    } catch (e) {
        result.error = e.message;
        return result;
    }
}

/**
 * Validate a single transaction
 */
async function validateTransaction(tx) {
    const result = {
        id: tx.id,
        protocol: tx.protocol,
        url: tx.request?.url,
        valid: false,
        level: 'none',
        error: null
    };

    const evidence = tx.forensic_evidence;
    if (!evidence) {
        result.error = 'No forensic evidence';
        return result;
    }

    const keylogRaw = evidence.keylog;
    const packets = evidence.raw_packets?.packets || [];
    // Process ALL packets (handshake + application) to get the full TLS stream
    // TLS 1.3 can have application data in "handshake" packets (post-Finished)
    const allPackets = packets; // Process both handshake and application packets

    if (!keylogRaw) {
        result.error = 'No keylog';
        return result;
    }

    if (allPackets.length === 0) {
        result.error = 'No packets';
        return result;
    }

    // Parse keylog string into object
    const keylog = parseKeylog(keylogRaw);
    if (!keylog) {
        result.error = 'Failed to parse keylog';
        return result;
    }

    // For TLS 1.2, extract server_random from ServerHello
    if (keylog.version === 'TLS12' && !keylog.keys.server_random) {
        const serverRandom = extractServerRandom(allPackets);
        if (serverRandom) {
            // Convert to hex string
            keylog.server_random = Array.from(serverRandom)
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        } else {
            result.error = 'TLS 1.2: server_random not found in ServerHello';
            return result;
        }
    }

    // Route to QUIC decryption for HTTP/3
    if (tx.protocol === 'HTTP/3') {
        return await validateQuicTransaction(tx, result, keylog, allPackets);
    }

    try {
        // Initialize TLS decryptor
        const decryptor = new TlsDecryptor();
        await decryptor.initialize(keylog);

        console.log(`\n[TX ${tx.id}] Starting decryption`);
        console.log(`  TLS Version: ${keylog.version}`);
        console.log(`  Has client key: ${!!decryptor.clientKey}`);
        console.log(`  Has server key: ${!!decryptor.serverKey}`);
        console.log(`  Has handshake keys: ${!!decryptor.handshakeClientKeys}`);

        // Debug: Print raw traffic secrets (first 16 bytes)
        const serverSecret = keylog.keys.server_traffic_secret_0;
        if (serverSecret) {
            console.log(`  Server traffic secret (first 32 hex): ${serverSecret.substring(0, 32)}`);
        }
        console.log(`  Total packets: ${allPackets.length}`);
        console.log(`  Handshake packets: ${allPackets.filter(p => p.packet_type === 'handshake').length}`);
        console.log(`  Application packets: ${allPackets.filter(p => p.packet_type === 'application').length}`);

        // CRITICAL: TLS records can span multiple TCP packets
        // We must reassemble the complete TLS stream before parsing records

        // Step 1: Extract TLS payloads and separate by direction
        // Use ALL packets to get the complete TLS stream
        // NEW: Find the first TLS record sequence number for each direction AND key type
        // TLS 1.3 has separate sequences for handshake vs application traffic
        const clientPayloads = [];
        const serverPayloads = [];

        // Track first sequence for each key type per direction
        let clientHandshakeStartSeq = null;
        let clientApplicationStartSeq = null;
        let serverHandshakeStartSeq = null;
        let serverApplicationStartSeq = null;

        for (const packet of allPackets) {
            const rawData = base64ToBytes(packet.data);
            const tlsData = extractTlsPayload(rawData);

            if (!tlsData || tlsData.length === 0) continue;

            const isHandshakeKey = packet.tls_key_type === 'handshake';
            const isApplicationKey = packet.tls_key_type === 'application';
            const hasSeq = packet.tls_record_seq !== undefined && packet.tls_record_seq !== null;

            if (packet.direction === 'client_to_server') {
                clientPayloads.push(tlsData);
                // Capture first sequence number for each key type
                if (hasSeq && isHandshakeKey && clientHandshakeStartSeq === null) {
                    clientHandshakeStartSeq = packet.tls_record_seq;
                }
                if (hasSeq && isApplicationKey && clientApplicationStartSeq === null) {
                    clientApplicationStartSeq = packet.tls_record_seq;
                }
            } else {
                serverPayloads.push(tlsData);
                if (hasSeq && isHandshakeKey && serverHandshakeStartSeq === null) {
                    serverHandshakeStartSeq = packet.tls_record_seq;
                }
                if (hasSeq && isApplicationKey && serverApplicationStartSeq === null) {
                    serverApplicationStartSeq = packet.tls_record_seq;
                }
            }
        }

        console.log(`  Client seq: handshake=${clientHandshakeStartSeq}, application=${clientApplicationStartSeq}`);
        console.log(`  Server seq: handshake=${serverHandshakeStartSeq}, application=${serverApplicationStartSeq}`);

        // Step 2: Concatenate into continuous streams
        const concatenate = (arrays) => {
            const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
            const result = new Uint8Array(totalLength);
            let offset = 0;
            for (const arr of arrays) {
                result.set(arr, offset);
                offset += arr.length;
            }
            return result;
        };

        const clientStream = clientPayloads.length > 0 ? concatenate(clientPayloads) : new Uint8Array(0);
        const serverStream = serverPayloads.length > 0 ? concatenate(serverPayloads) : new Uint8Array(0);

        console.log(`  Client stream: ${clientStream.length} bytes from ${clientPayloads.length} packets`);
        console.log(`  Server stream: ${serverStream.length} bytes from ${serverPayloads.length} packets`);

        if (serverStream.length > 0) {
            const serverFirst = Buffer.from(serverStream.slice(0, Math.min(20, serverStream.length))).toString('hex');
            console.log(`  Server stream first bytes: ${serverFirst}`);
        }

        // Step 3: Parse complete TLS records from reassembled streams
        const clientRecords = parseTlsRecords(clientStream);
        const serverRecords = parseTlsRecords(serverStream);

        console.log(`  Client records: ${clientRecords.length}`);
        console.log(`  Server records: ${serverRecords.length}`);

        let decryptedAny = false;
        let allPlaintext = [];

        // Step 4: Decrypt client records
        // TLS 1.3 has SEPARATE sequence counters for handshake vs application traffic
        // We track both and use the key type hint from forensic evidence
        let clientHandshakeSeq = clientHandshakeStartSeq ?? 0;
        let clientApplicationSeq = clientApplicationStartSeq ?? 0;
        const haveClientHandshakeSeq = clientHandshakeStartSeq !== null;
        const haveClientApplicationSeq = clientApplicationStartSeq !== null;

        for (let i = 0; i < clientRecords.length; i++) {
            const record = clientRecords[i];
            const typeName = {
                20: 'CHANGE_CIPHER_SPEC',
                21: 'ALERT',
                22: 'HANDSHAKE',
                23: 'APPLICATION_DATA'
            }[record.type] || `UNKNOWN(${record.type})`;

            console.log(`  [Client Record ${i + 1}] Type: ${typeName}, Size: ${record.data.length}`);

            if (record.type === TLS_CONTENT_TYPE.APPLICATION_DATA) {
                try {
                    // Try with application keys first (most common), then handshake keys
                    // Pass both sequences and let decryptor try the right one
                    const appSeq = haveClientApplicationSeq ? clientApplicationSeq : null;
                    const hsSeq = haveClientHandshakeSeq ? clientHandshakeSeq : null;

                    // Try application keys first with application sequence
                    let decrypted;
                    let seqSource = '';
                    try {
                        decrypted = await decryptor.decryptRecord(record.raw, 'client', clientApplicationSeq, appSeq, 'application');
                        clientApplicationSeq = decrypted.seq + 1;
                        seqSource = haveClientApplicationSeq ? ' [exact app]' : ' [searched app]';
                    } catch (e1) {
                        // Try handshake keys with handshake sequence
                        decrypted = await decryptor.decryptRecord(record.raw, 'client', clientHandshakeSeq, hsSeq, 'handshake');
                        clientHandshakeSeq = decrypted.seq + 1;
                        seqSource = haveClientHandshakeSeq ? ' [exact hs]' : ' [searched hs]';
                    }

                    decryptedAny = true;
                    allPlaintext.push({
                        direction: 'client',
                        data: decrypted.plaintext
                    });
                    console.log(`    ✓ Decrypted ${decrypted.plaintext.length} bytes (seq ${decrypted.seq}${seqSource})`);
                } catch (e) {
                    console.log(`    ✗ Decryption failed: ${e.message}`);
                }
            }
        }

        // Step 5: Decrypt server records
        // TLS 1.3 has SEPARATE sequence counters for handshake vs application traffic
        let serverHandshakeSeq = serverHandshakeStartSeq ?? 0;
        let serverApplicationSeq = serverApplicationStartSeq ?? 0;
        const haveServerHandshakeSeq = serverHandshakeStartSeq !== null;
        const haveServerApplicationSeq = serverApplicationStartSeq !== null;

        for (let i = 0; i < serverRecords.length; i++) {
            const record = serverRecords[i];
            const typeName = {
                20: 'CHANGE_CIPHER_SPEC',
                21: 'ALERT',
                22: 'HANDSHAKE',
                23: 'APPLICATION_DATA'
            }[record.type] || `UNKNOWN(${record.type})`;

            console.log(`  [Server Record ${i + 1}] Type: ${typeName}, Size: ${record.data.length}`);

            if (record.type === TLS_CONTENT_TYPE.APPLICATION_DATA) {
                try {
                    // Try with handshake keys first for server (encrypted handshake comes first)
                    // Then application keys for actual data
                    const appSeq = haveServerApplicationSeq ? serverApplicationSeq : null;
                    const hsSeq = haveServerHandshakeSeq ? serverHandshakeSeq : null;

                    let decrypted;
                    let seqSource = '';
                    try {
                        // Try handshake keys first for server (EncryptedExtensions, etc.)
                        decrypted = await decryptor.decryptRecord(record.raw, 'server', serverHandshakeSeq, hsSeq, 'handshake');
                        serverHandshakeSeq = decrypted.seq + 1;
                        seqSource = haveServerHandshakeSeq ? ' [exact hs]' : ' [searched hs]';
                    } catch (e1) {
                        // Try application keys
                        decrypted = await decryptor.decryptRecord(record.raw, 'server', serverApplicationSeq, appSeq, 'application');
                        serverApplicationSeq = decrypted.seq + 1;
                        seqSource = haveServerApplicationSeq ? ' [exact app]' : ' [searched app]';
                    }

                    decryptedAny = true;
                    allPlaintext.push({
                        direction: 'server',
                        data: decrypted.plaintext
                    });
                    console.log(`    ✓ Decrypted ${decrypted.plaintext.length} bytes (seq ${decrypted.seq}${seqSource})`);
                } catch (e) {
                    console.log(`    ✗ Decryption failed: ${e.message}`);
                }
            }
        }

        if (!decryptedAny) {
            console.log(`  RESULT: Failed to decrypt any records\n`);
            result.error = 'Failed to decrypt any records';
            return result;
        }

        console.log(`  RESULT: Successfully decrypted ${allPlaintext.length} record(s)\n`);
        result.level = 'decrypt';
        result.valid = true;

        // For HTTP/2, try to parse frames and find the stream
        if (tx.protocol === 'HTTP/2' && evidence.h2_stream_id) {
            const streamId = evidence.h2_stream_id;

            // Use new dual HPACK snapshot structure (request + response tables)
            const requestSnapshot = evidence.hpack_request_table;
            const responseSnapshot = evidence.hpack_response_table;

            if (!requestSnapshot || !responseSnapshot) {
                result.error = 'Missing HPACK snapshots';
                return result;
            }

            const requestHpack = new HpackDecoder(requestSnapshot);
            const responseHpack = new HpackDecoder(responseSnapshot);

            let foundRequestHeaders = false;
            let foundResponseHeaders = false;
            let parsedRequest = null;
            let parsedResponse = null;

            // For hash verification
            let requestHeaders = [];
            let requestBody = new Uint8Array(0);
            let responseHeaders = [];
            let responseBody = new Uint8Array(0);

            for (const { direction, data } of allPlaintext) {
                // Skip HTTP/2 preface if present
                let offset = 0;
                const preface = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';
                const prefaceBytes = new TextEncoder().encode(preface);
                if (data.length >= prefaceBytes.length) {
                    let isPreface = true;
                    for (let j = 0; j < prefaceBytes.length; j++) {
                        if (data[j] !== prefaceBytes[j]) { isPreface = false; break; }
                    }
                    if (isPreface) offset = prefaceBytes.length;
                }

                try {
                    const frames = parseFrames(data.slice(offset));
                    for (const frame of frames) {
                        if (frame.streamId !== streamId) continue;

                        if (frame.type === FrameType.HEADERS) {
                            try {
                                // Use appropriate HPACK decoder based on direction
                                const decoder = direction === 'client' ? requestHpack : responseHpack;
                                // Extract header block (strips padding and priority fields)
                                const headerBlock = extractHeaderBlock(frame.payload, frame.flags);
                                const headers = decoder.decode(headerBlock);
                                const headerMap = {};
                                for (const [name, value] of headers) {
                                    headerMap[name] = value;
                                }

                                if (direction === 'client') {
                                    foundRequestHeaders = true;
                                    requestHeaders = headers; // Store for hash verification
                                    parsedRequest = {
                                        method: headerMap[':method'],
                                        path: headerMap[':path'],
                                        authority: headerMap[':authority'],
                                        scheme: headerMap[':scheme']
                                    };
                                } else {
                                    foundResponseHeaders = true;
                                    responseHeaders = headers; // Store for hash verification
                                    parsedResponse = {
                                        status: parseInt(headerMap[':status'], 10)
                                    };
                                }
                            } catch (e) {
                                // HPACK decode failed
                            }
                        }

                        // Collect DATA frames for hash verification
                        if (frame.type === FrameType.DATA && frame.data) {
                            if (direction === 'client') {
                                const newBody = new Uint8Array(requestBody.length + frame.data.length);
                                newBody.set(requestBody);
                                newBody.set(frame.data, requestBody.length);
                                requestBody = newBody;
                            } else {
                                const newBody = new Uint8Array(responseBody.length + frame.data.length);
                                newBody.set(responseBody);
                                newBody.set(frame.data, responseBody.length);
                                responseBody = newBody;
                            }
                        }
                    }
                } catch (e) {
                    // Frame parsing failed
                }
            }

            if (foundRequestHeaders || foundResponseHeaders) {
                result.level = 'parse';

                // Compare with claimed values
                if (parsedRequest && tx.request) {
                    const claimedUrl = new URL(tx.request.url);
                    const matches =
                        parsedRequest.method === tx.request.method &&
                        parsedRequest.path === claimedUrl.pathname + claimedUrl.search &&
                        parsedRequest.authority === claimedUrl.host;

                    if (matches) {
                        result.level = 'full';
                    } else {
                        result.mismatch = {
                            claimed: {
                                method: tx.request.method,
                                path: claimedUrl.pathname + claimedUrl.search,
                                authority: claimedUrl.host
                            },
                            parsed: parsedRequest
                        };
                    }
                }

            }
        }

        return result;
    } catch (e) {
        result.error = e.message;
        return result;
    }
}

async function main() {
    console.log(`Validating transactions from: ${inputFile}\n`);

    const rl = createInterface({
        input: createReadStream(inputFile),
        crlfDelay: Infinity
    });

    const results = {
        total: 0,
        withEvidence: 0,
        valid: 0,
        levels: { verified: 0, full: 0, parse: 0, decrypt: 0, none: 0 },
        failed: 0,
        noEvidence: 0,
        mismatches: 0,
        byProtocol: {},
        failures: []
    };

    const startTime = Date.now();
    let count = 0;

    for await (const line of rl) {
        if (!line.trim()) continue;
        const wrapper = JSON.parse(line);
        const isWebSocket = wrapper.type === 'web_socket_message';
        const tx = (wrapper.type === 'transaction' || isWebSocket) ? wrapper.data : wrapper;

        results.total++;
        count++;
        if (count % 50 === 0) process.stdout.write(`Processed: ${count}...`);

        // Route WebSocket messages to dedicated validator
        const result = isWebSocket
            ? await validateWebSocketMessage(tx)
            : await validateTransaction(tx);

        const protocol = result.protocol || tx.protocol || 'unknown';
        if (!results.byProtocol[protocol]) {
            results.byProtocol[protocol] = { valid: 0, failed: 0, errors: {} };
        }

        if (!result.error && result.valid) {
            results.withEvidence++;
            results.valid++;
            results.levels[result.level]++;
            results.byProtocol[protocol].valid++;
        } else if (result.error === 'No forensic evidence') {
            results.noEvidence++;
        } else if (result.mismatch) {
            results.withEvidence++;
            results.mismatches++;
            results.byProtocol[protocol].failed++;
            results.failures.push({ id: tx.id, protocol, error: 'Fields don\'t match', mismatch: result.mismatch });
        } else {
            results.withEvidence++;
            results.failed++;
            results.byProtocol[protocol].failed++;
            const errKey = result.error || 'unknown';
            results.byProtocol[protocol].errors[errKey] = (results.byProtocol[protocol].errors[errKey] || 0) + 1;
            results.failures.push({ id: tx.id, protocol, error: result.error });
        }
    }

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);

    console.log('============================================================\n');
    console.log('Results:');
    console.log(`  Total transactions: ${results.total}`);
    console.log(`  With forensic evidence: ${results.withEvidence}`);
    console.log(`  Valid: ${results.valid} (${(results.valid / results.withEvidence * 100).toFixed(1)}%)`);
    console.log(`    - Full (decrypt+parse+match): ${results.levels.full}`);
    console.log(`    - Parse (decrypt+parse, no comparison): ${results.levels.parse}`);
    console.log(`    - Decrypt only: ${results.levels.decrypt}`);
    console.log(`    - Connection setup: ${results.levels.none}`);
    console.log(`  Field mismatches: ${results.mismatches}`);
    console.log(`  Failed: ${results.failed}`);
    console.log(`  No evidence: ${results.noEvidence}`);
    console.log(`  Time: ${elapsed}s`);

    // Show TLS/TCP only stats (excluding HTTP/3 which uses QUIC)
    const tlsTcpValid = (results.byProtocol['HTTP/1.1']?.valid || 0) +
                        (results.byProtocol['HTTP/2']?.valid || 0) +
                        (results.byProtocol['WebSocket']?.valid || 0);
    const tlsTcpTotal = results.withEvidence - (results.byProtocol['HTTP/3']?.valid || 0) - (results.byProtocol['HTTP/3']?.failed || 0);
    console.log(`\n  TLS/TCP only (excl HTTP/3): ${tlsTcpValid}/${tlsTcpTotal} (${(tlsTcpValid / tlsTcpTotal * 100).toFixed(1)}%)`);

    console.log('\nFailures by protocol:');
    for (const [proto, stats] of Object.entries(results.byProtocol)) {
        if (stats.failed > 0) {
            const errorSummary = Object.entries(stats.errors)
                .map(([e, c]) => `${e.substring(0, 20)}: ${c}`)
                .join(', ');
            console.log(`  ${proto}: ${stats.failed} (${errorSummary})`);

            // Show first 2 failures for this protocol
            const protoFailures = results.failures.filter(f => f.protocol === proto).slice(0, 2);
            for (const f of protoFailures) {
                console.log(`    → ${f.id}: ${f.error}`);
            }
        }
    }

    if (results.failures.length > 0) {
        console.log(`\nFirst 20 failures:`);
        for (const f of results.failures.slice(0, 20)) {
            console.log(`  - ${f.id} [${f.protocol}]: ${f.error}`);
        }
        if (results.failures.length > 20) {
            console.log(`  ... and ${results.failures.length - 20} more`);
        }
    }
}

main().catch(console.error);
