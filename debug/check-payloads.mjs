#!/usr/bin/env node
import { base64ToBytes } from './js/crypto/hash.js';
import fs from 'fs';

const line = fs.readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').split('\n')[0];
const tx = JSON.parse(line).data;
const packets = tx.forensic_evidence.raw_packets.packets;

function extractTls(rawData) {
    // Check if starts with Ethernet header (14 bytes)
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
        // IPv6
        offset += 40;
        const tcpDataOffset = ((rawData[offset + 12] >> 4) & 0xF) * 4;
        offset += tcpDataOffset;
    } else if (actualIpVersion === 4) {
        // IPv4
        const ihl = (rawData[offset] & 0x0F) * 4;
        offset += ihl;
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
    if (tlsData && tlsData.length > 0) clientPayloads.push(tlsData);
}

console.log('Client payloads:', clientPayloads.length);
for (let i = 0; i < clientPayloads.length; i++) {
    const p = clientPayloads[i];
    const first5 = Buffer.from(p.slice(0, Math.min(5, p.length))).toString('hex');
    console.log(`  Payload ${i + 1}: length=${p.length}, first 5 bytes: ${first5}`);
}

const totalLength = clientPayloads.reduce((sum, arr) => sum + arr.length, 0);
const clientStream = new Uint8Array(totalLength);
let offset = 0;
for (const arr of clientPayloads) {
    clientStream.set(arr, offset);
    offset += arr.length;
}

console.log('\nClient stream length:', clientStream.length);
console.log('First 20 bytes:', Buffer.from(clientStream.slice(0, 20)).toString('hex'));
