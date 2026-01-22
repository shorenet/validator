#!/usr/bin/env node
/**
 * Test decryption on a single transaction to debug issues.
 * Imports real functions from batch-validate.mjs
 */
import { webcrypto } from 'crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { base64ToBytes } from './js/crypto/hash.js';
import { TlsDecryptor, parseTlsRecords, TLS_CONTENT_TYPE } from './js/crypto/tls.js';
import fs from 'fs';

// Read first transaction
const lines = fs.readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').split('\n');
const tx = JSON.parse(lines[0]).data;

console.log('=== Transaction ===');
console.log('ID:', tx.id);
console.log('Protocol:', tx.protocol);
console.log('URL:', tx.request.url);
console.log('');

// Copy parseKeylog from batch-validate
function parseKeylog(keylogStr) {
    const keys = {};
    const lines = keylogStr.split('\n');
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const parts = trimmed.split(/\s+/);
        if (parts.length < 3) continue;
        const [label, clientRandom, secret] = parts;
        keys[label.toLowerCase()] = secret;
    }
    return {
        version: keylogStr.includes('CLIENT_TRAFFIC_SECRET_0') ? 'TLS13' : 'TLS12',
        keys
    };
}

// Copy extractTlsPayload from batch-validate
function extractTlsPayload(data) {
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
        const payload = data.slice(udpStart + 8);
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

// Parse keylog
const keylog = parseKeylog(tx.forensic_evidence.keylog);
console.log('=== Keylog ===');
console.log('Version:', keylog.version);
console.log('Keys:', Object.keys(keylog.keys));
console.log('');

// Initialize decryptor
const decryptor = new TlsDecryptor();
await decryptor.initialize(keylog);

console.log('=== Decryptor ===');
console.log('Has client application key:', !!decryptor.clientKey);
console.log('Has server application key:', !!decryptor.serverKey);
console.log('Has client handshake key:', !!decryptor.handshakeClientKeys);
console.log('Has server handshake key:', !!decryptor.handshakeServerKeys);
console.log('');

// Reassemble TLS streams
const packets = tx.forensic_evidence.raw_packets.packets;
const clientPayloads = [];
const serverPayloads = [];

for (const packet of packets) {
    const rawData = base64ToBytes(packet.data);
    const tlsData = extractTlsPayload(rawData);
    if (!tlsData || tlsData.length === 0) continue;

    if (packet.direction === 'client_to_server') {
        clientPayloads.push(tlsData);
    } else {
        serverPayloads.push(tlsData);
    }
}

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

const clientStream = concatenate(clientPayloads);
const serverStream = concatenate(serverPayloads);

console.log('=== Streams ===');
console.log('Client stream:', clientStream.length, 'bytes from', clientPayloads.length, 'packets');
console.log('Server stream:', serverStream.length, 'bytes from', serverPayloads.length, 'packets');
console.log('');

// Parse TLS records
const clientRecords = parseTlsRecords(clientStream);
const serverRecords = parseTlsRecords(serverStream);

console.log('=== TLS Records ===');
console.log('Client records:', clientRecords.length);
console.log('Server records:', serverRecords.length);
console.log('');

// Try to decrypt client APPLICATION_DATA records
console.log('=== Client Decryption ===');
let clientHint = 0;
for (let i = 0; i < clientRecords.length; i++) {
    const record = clientRecords[i];
    const typeName = {
        20: 'CHANGE_CIPHER_SPEC',
        21: 'ALERT',
        22: 'HANDSHAKE',
        23: 'APPLICATION_DATA'
    }[record.type] || `UNKNOWN(${record.type})`;

    console.log(`Record ${i + 1}: type=${typeName}, size=${record.data.length}`);

    if (record.type === TLS_CONTENT_TYPE.APPLICATION_DATA) {
        try {
            const result = await decryptor.decryptRecord(record.raw, 'client', clientHint);
            console.log(`  ✓ SUCCESS: seq=${result.seq}, keyType=${result.keyType}, plaintext=${result.plaintext.length} bytes`);
            clientHint = result.seq + 1;
        } catch (e) {
            console.log(`  ✗ FAILED: ${e.message}`);
        }
    }
}

console.log('');
console.log('=== Server Decryption ===');
let serverHint = 0;
for (let i = 0; i < serverRecords.length; i++) {
    const record = serverRecords[i];
    const typeName = {
        20: 'CHANGE_CIPHER_SPEC',
        21: 'ALERT',
        22: 'HANDSHAKE',
        23: 'APPLICATION_DATA'
    }[record.type] || `UNKNOWN(${record.type})`;

    console.log(`Record ${i + 1}: type=${typeName}, size=${record.data.length}`);

    if (record.type === TLS_CONTENT_TYPE.APPLICATION_DATA) {
        try {
            const result = await decryptor.decryptRecord(record.raw, 'server', serverHint);
            console.log(`  ✓ SUCCESS: seq=${result.seq}, keyType=${result.keyType}, plaintext=${result.plaintext.length} bytes`);
            serverHint = result.seq + 1;
        } catch (e) {
            console.log(`  ✗ FAILED: ${e.message}`);
        }
    }
}
