#!/usr/bin/env node
import { base64ToBytes } from './js/crypto/hash.js';
import { parseTlsRecords } from './js/crypto/tls.js';
import fs from 'fs';

const line = fs.readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').split('\n')[0];
const tx = JSON.parse(line).data;
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
    if (tlsData && tlsData.length > 0) clientPayloads.push(tlsData);
}

const totalLength = clientPayloads.reduce((sum, arr) => sum + arr.length, 0);
const clientStream = new Uint8Array(totalLength);
let offset = 0;
for (const arr of clientPayloads) {
    clientStream.set(arr, offset);
    offset += arr.length;
}

const records = parseTlsRecords(clientStream);
for (let i = 0; i < Math.min(records.length, 10); i++) {
    const r = records[i];
    const header = r.raw.slice(0, 5);
    console.log(`Record ${i+1}: type=0x${header[0].toString(16).padStart(2, '0')} version=0x${header[1].toString(16)}${header[2].toString(16).padStart(2, '0')} length=${(header[3] << 8) | header[4]}`);
}
