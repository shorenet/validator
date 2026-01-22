#!/usr/bin/env node
import { webcrypto } from 'crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { base64ToBytes } from './js/crypto/hash.js';
import { hexToBytes, deriveTrafficKeys, decryptTls13Record } from './js/crypto/tls.js';
import fs from 'fs';

const line = fs.readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').split('\n')[0];
const tx = JSON.parse(line).data;

console.log('Testing single TLS record decryption');
console.log('Transaction:', tx.id);
console.log('');

// Parse keylog
const keylogLines = tx.forensic_evidence.keylog.split('\n');
const secrets = {};
for (const line of keylogLines) {
    if (!line.trim()) continue;
    const [label, clientRandom, secret] = line.split(/\s+/);
    secrets[label] = secret;
}

console.log('Keys from keylog:');
console.log('  CLIENT_TRAFFIC_SECRET_0:', secrets.CLIENT_TRAFFIC_SECRET_0.substring(0, 32) + '...');
console.log('  SERVER_TRAFFIC_SECRET_0:', secrets.SERVER_TRAFFIC_SECRET_0.substring(0, 32) + '...');
console.log('');

// Derive keys
const serverSecret = hexToBytes(secrets.SERVER_TRAFFIC_SECRET_0);
console.log('Server secret bytes (first 16):', Buffer.from(serverSecret.slice(0, 16)).toString('hex'));

const serverKeys = await deriveTrafficKeys(serverSecret);
console.log('Server IV (first 12 bytes):', Buffer.from(serverKeys.iv).toString('hex'));
console.log('');

// Get Server Record 3 (the big 4560-byte APPLICATION_DATA record)
// This is the first encrypted record from the server

// First, reassemble the server stream
const packets = tx.forensic_evidence.raw_packets.packets;
const serverPackets = packets.filter(p => p.direction === 'server_to_client');

console.log('Server packets:', serverPackets.length);

// Extract TLS payloads
function extractTls(rawData) {
    const ipVersion = (rawData[0] >> 4) & 0xF;
    let offset = 0;
    if (ipVersion === 6) {
        offset = 40;
        const tcpDataOffset = ((rawData[offset + 12] >> 4) & 0xF) * 4;
        offset += tcpDataOffset;
    } else if (ipVersion === 4) {
        const ihl = (rawData[0] & 0x0F) * 4;
        offset = ihl;
        const tcpDataOffset = ((rawData[offset + 12] >> 4) & 0xF) * 4;
        offset += tcpDataOffset;
    }
    return rawData.slice(offset);
}

const serverPayloads = [];
for (const pkt of serverPackets) {
    const rawData = base64ToBytes(pkt.data);
    const tlsData = extractTls(rawData);
    if (tlsData && tlsData.length > 0) {
        serverPayloads.push(tlsData);
    }
}

// Concatenate
const totalLength = serverPayloads.reduce((sum, arr) => sum + arr.length, 0);
const serverStream = new Uint8Array(totalLength);
let offset = 0;
for (const arr of serverPayloads) {
    serverStream.set(arr, offset);
    offset += arr.length;
}

console.log('Server stream:', serverStream.length, 'bytes');
console.log('First bytes:', Buffer.from(serverStream.slice(0, 20)).toString('hex'));
console.log('');

// Parse TLS records
function parseTlsRecords(data) {
    const records = [];
    let offset = 0;
    while (offset + 5 <= data.length) {
        const type = data[offset];
        const version = (data[offset + 1] << 8) | data[offset + 2];
        const length = (data[offset + 3] << 8) | data[offset + 4];
        if (offset + 5 + length > data.length) break;
        records.push({
            type,
            version,
            length,
            raw: data.slice(offset, offset + 5 + length)
        });
        offset += 5 + length;
    }
    return records;
}

const records = parseTlsRecords(serverStream);
console.log('Server records:', records.length);
for (let i = 0; i < records.length; i++) {
    console.log(`  Record ${i + 1}: type=${records[i].type}, length=${records[i].length}`);
}
console.log('');

// Get Record 3 (index 2) - the first APPLICATION_DATA record
const record3 = records[2];
if (record3.type !== 23) {
    console.log('Record 3 is not APPLICATION_DATA!');
    process.exit(1);
}

console.log('Attempting to decrypt Record 3 (first APPLICATION_DATA)');
console.log('  Record length:', record3.length);
console.log('  Full record size:', record3.raw.length);
console.log('  Ciphertext starts at byte 5');
console.log('');

// Extract ciphertext
const ciphertext = record3.raw.slice(5);
console.log('Ciphertext length:', ciphertext.length);
console.log('Ciphertext first bytes:', Buffer.from(ciphertext.slice(0, 20)).toString('hex'));
console.log('');

// Try to decrypt with seq=0
console.log('Trying decryption with seq=0...');
try {
    const result = await decryptTls13Record(ciphertext, serverKeys.key, serverKeys.iv, 0n);
    console.log('SUCCESS!');
    console.log('Plaintext length:', result.plaintext.length);
    console.log('Plaintext first bytes:', Buffer.from(result.plaintext.slice(0, Math.min(50, result.plaintext.length))).toString('hex'));
    console.log('Content type:', result.contentType);
} catch (e) {
    console.log('FAILED:', e.message);
    console.log('');
    console.log('This means the JavaScript TLS decryption has a bug,');
    console.log('or the keys are being derived incorrectly.');
}
