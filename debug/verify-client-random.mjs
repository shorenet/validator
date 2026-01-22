#!/usr/bin/env node
import { base64ToBytes } from './js/crypto/hash.js';
import fs from 'fs';

const line = fs.readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').split('\n')[0];
const tx = JSON.parse(line).data;

// Get keylog client_random
const keylogLines = tx.forensic_evidence.keylog.split('\n');
const firstLine = keylogLines[0];
const keylogClientRandom = firstLine.split(/\s+/)[1];

console.log('Keylog client_random:', keylogClientRandom);
console.log('');

// Find ClientHello packet
const packets = tx.forensic_evidence.raw_packets.packets;
const chPacket = packets.find(p => p.packet_type === 'handshake' && p.direction === 'client_to_server');

if (!chPacket) {
    console.log('ClientHello packet not found!');
    process.exit(1);
}

// Extract TLS payload
const rawData = base64ToBytes(chPacket.data);

// Skip IPv6 header (40 bytes) + TCP header
let offset = 0;
const ipVersion = (rawData[0] >> 4) & 0xF;
if (ipVersion === 6) {
    offset = 40;
    const tcpDataOffset = ((rawData[offset + 12] >> 4) & 0xF) * 4;
    offset += tcpDataOffset;
} else if (ipVersion === 4) {
    const ihl = (rawData[0] & 0x0F) * 4;
    offset = ihl;
    const tcpDataOffset = ((rawData[offset + 12] >> 4) & 0xF) * 4;
    offset += tcpDataOffset;
} else {
    console.log('Unknown IP version:', ipVersion);
    process.exit(1);
}

const tlsData = rawData.slice(offset);

// Parse TLS record header
// TLS record: type(1) + version(2) + length(2) + data
const recordType = tlsData[0];
const recordVersion = (tlsData[1] << 8) | tlsData[2];
const recordLength = (tlsData[3] << 8) | tlsData[4];

console.log(`TLS Record: type=${recordType} (0x${recordType.toString(16)}), version=0x${recordVersion.toString(16)}, length=${recordLength}`);

if (recordType !== 0x16) {
    console.log('Not a HANDSHAKE record!');
    process.exit(1);
}

// Handshake message: type(1) + length(3) + data
const handshakeData = tlsData.slice(5);
const handshakeType = handshakeData[0];
const handshakeLength = (handshakeData[1] << 16) | (handshakeData[2] << 8) | handshakeData[3];

console.log(`Handshake: type=${handshakeType} (0x${handshakeType.toString(16)}), length=${handshakeLength}`);

if (handshakeType !== 0x01) {
    console.log('Not a ClientHello!');
    process.exit(1);
}

// ClientHello structure:
// - client_version(2)
// - random(32) ← This is what we want!
// - session_id_length(1)
// - ...

const clientHelloData = handshakeData.slice(4);
const clientVersion = (clientHelloData[0] << 8) | clientHelloData[1];
const clientRandom = clientHelloData.slice(2, 34);

console.log(`Client version: 0x${clientVersion.toString(16)}`);
console.log(`Client random: ${Buffer.from(clientRandom).toString('hex')}`);
console.log('');

// Compare
if (Buffer.from(clientRandom).toString('hex') === keylogClientRandom) {
    console.log('✓ Client random MATCHES keylog!');
} else {
    console.log('✗ Client random DOES NOT MATCH keylog!');
    console.log('  This means the keylog is for a different connection.');
}
