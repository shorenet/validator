#!/usr/bin/env node
import { webcrypto } from 'crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { base64ToBytes } from './js/crypto/hash.js';
import { TlsDecryptor, parseTlsRecords, TLS_CONTENT_TYPE } from './js/crypto/tls.js';
import fs from 'fs';

const line = fs.readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').split('\n')[0];
const tx = JSON.parse(line).data;

console.log('Comparing Keel vs Validator decryption inputs');
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

console.log('CLIENT_TRAFFIC_SECRET_0:', keylog.keys.client_traffic_secret_0);
console.log('');

// Initialize decryptor
const decryptor = new TlsDecryptor();
await decryptor.initialize(keylog);

// Reassemble stream
const packets = tx.forensic_evidence.raw_packets.packets;

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

const clientPayloads = [];
for (const pkt of packets) {
    if (pkt.direction !== 'client_to_server') continue;
    const rawData = base64ToBytes(pkt.data);
    const tlsData = extractTls(rawData);
    if (tlsData && tlsData.length > 0) {
        clientPayloads.push(tlsData);
    }
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

// Find first APPLICATION_DATA record
let firstAppData = null;
for (const record of clientRecords) {
    if (record.type === TLS_CONTENT_TYPE.APPLICATION_DATA) {
        firstAppData = record;
        break;
    }
}

if (!firstAppData) {
    console.log('No APPLICATION_DATA record found!');
    process.exit(1);
}

// Extract ciphertext
const ciphertext = firstAppData.raw.slice(5);
console.log('First CLIENT APPLICATION_DATA record:');
console.log('  Size:', ciphertext.length);
console.log('  First bytes:', Buffer.from(ciphertext.slice(0, 20)).toString('hex'));
console.log('');

// Export client key/iv for comparison
const clientKeyBytes = await crypto.subtle.exportKey('raw', decryptor.clientKey);
const clientKey = Buffer.from(clientKeyBytes).toString('hex');
const clientIv = Buffer.from(decryptor.clientIv).toString('hex');

console.log('Validator derived CLIENT keys:');
console.log('  Key:', clientKey);
console.log('  IV:', clientIv);
console.log('');

console.log('From Keel replay_daemon.log (79-byte CLIENT record):');
console.log('  ciphertext_first=bd507db2d189e4d5650f88a8d93b0e3d125bc501');
console.log('  key=fbaa72491459cc87fa6c9d4c2a190fe1');
console.log('  iv=e33ba190834c3c3a7dc6eebd');
console.log('');

console.log('COMPARISON:');
if (Buffer.from(ciphertext.slice(0, 20)).toString('hex') === 'bd507db2d189e4d5650f88a8d93b0e3d125bc501') {
    console.log('  ✓ Ciphertext MATCHES');
} else {
    console.log('  ✗ Ciphertext MISMATCH!');
}

if (clientKey === 'fbaa72491459cc87fa6c9d4c2a190fe1') {
    console.log('  ✓ Key MATCHES');
} else {
    console.log('  ✗ Key MISMATCH!');
    console.log('    Expected: fbaa72491459cc87fa6c9d4c2a190fe1');
    console.log('    Got:      ' + clientKey);
}

if (clientIv === 'e33ba190834c3c3a7dc6eebd') {
    console.log('  ✓ IV MATCHES');
} else {
    console.log('  ✗ IV MISMATCH!');
    console.log('    Expected: e33ba190834c3c3a7dc6eebd');
    console.log('    Got:      ' + clientIv);
}
