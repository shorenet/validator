#!/usr/bin/env node
import { webcrypto } from 'crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { base64ToBytes } from './js/crypto/hash.js';
import { TlsDecryptor, parseTlsRecords, TLS_CONTENT_TYPE } from './js/crypto/tls.js';
import fs from 'fs';

// Read first transaction
const line = fs.readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').split('\n')[0];
const tx = JSON.parse(line).data;

console.log('Transaction:', tx.id);
console.log('Protocol:', tx.protocol);
console.log('URL:', tx.request.url);
console.log('');

// Parse keylog
function parseKeylog(keylogStr) {
    const keys = {};
    const lines = keylogStr.split('\n');
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const parts = trimmed.split(/\s+/);
        if (parts.length < 3) continue;
        const [label, , secret] = parts;
        keys[label.toLowerCase()] = secret;
    }
    return { version: 'TLS13', keys };
}

const keylog = parseKeylog(tx.forensic_evidence.keylog);
console.log('Keys:', Object.keys(keylog.keys));

// Initialize decryptor
const decryptor = new TlsDecryptor();
await decryptor.initialize(keylog);

console.log('Has application keys:', !!decryptor.clientKey);
console.log('Has handshake keys:', !!decryptor.handshakeClientKeys);
console.log('');

// Extract TLS payload (handle Ethernet header)
function extractTls(rawData) {
    const firstByte = rawData[0];
    const ipVersion = (firstByte >> 4) & 0xF;
    let offset = 0;

    // If not 4 or 6, assume Ethernet header
    if (ipVersion !== 4 && ipVersion !== 6) {
        offset = 14; // Skip Ethernet header
    }

    // Parse IP header
    const ipByte = rawData[offset];
    const actualIpVersion = (ipByte >> 4) & 0xF;

    if (actualIpVersion === 6) {
        offset += 40;
        const tcpDataOffset = ((rawData[offset + 12] >> 4) & 0xF) * 4;
        offset += tcpDataOffset;
    } else if (actualIpVersion === 4) {
        const ihl = (rawData[offset] & 0x0F) * 4;
        offset += ihl;
        const tcpDataOffset = ((rawData[offset + 12] >> 4) & 0xF) * 4;
        offset += tcpDataOffset;
    }

    return rawData.slice(offset);
}

// Reassemble client stream
const packets = tx.forensic_evidence.raw_packets.packets;
const clientPayloads = [];
for (const pkt of packets) {
    if (pkt.direction !== 'client_to_server') continue;
    const rawData = base64ToBytes(pkt.data);
    const tlsData = extractTls(rawData);
    if (tlsData && tlsData.length > 0) clientPayloads.push(tlsData);
}

const totalLength = clientPayloads.reduce((sum, arr) => sum + arr.length, 0);
const clientStream = new Uint8Array(totalLength);
let offset = 0;
for (const arr of clientPayloads) {
    clientStream.set(arr, offset);
    offset += arr.length;
}

const clientRecords = parseTlsRecords(clientStream);
console.log('Client records:', clientRecords.length);

// Try to decrypt each APPLICATION_DATA record
for (let i = 0; i < clientRecords.length; i++) {
    const record = clientRecords[i];
    if (record.type !== TLS_CONTENT_TYPE.APPLICATION_DATA) continue;

    console.log(`\nRecord ${i + 1}: size=${record.data.length}`);
    console.log('  Header:', Buffer.from(record.raw.slice(0, 5)).toString('hex'));
    console.log('  First 20 bytes of ciphertext:', Buffer.from(record.data.slice(0, 20)).toString('hex'));

    try {
        const result = await decryptor.decryptRecord(record.raw, 'client', 0);
        console.log(`  ✓ Decrypted with ${result.keyType} key, seq=${result.seq}, plaintext=${result.plaintext.length} bytes`);
    } catch (e) {
        console.log(`  ✗ FAILED: ${e.message}`);
    }
}
