#!/usr/bin/env node
import { webcrypto } from 'crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;
import { base64ToBytes } from './js/crypto/hash.js';
import { TlsDecryptor, parseTlsRecords, TLS_CONTENT_TYPE } from './js/crypto/tls.js';
import fs from 'fs';

const line = fs.readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').split('\n')[0];
const tx = JSON.parse(line).data;

function parseKeylog(keylogStr) {
    const keys = {};
    for (const line of keylogStr.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const parts = trimmed.split(/\s+/);
        if (parts.length < 3) continue;
        keys[parts[0].toLowerCase()] = parts[2];
    }
    return { version: 'TLS13', keys };
}

function extractTlsPayload(data) {
    const firstByte = data[0];
    if (firstByte >= 20 && firstByte <= 23) return data;
    if ((data[0] >> 4) === 4) {
        const ihl = (data[0] & 0x0f) * 4;
        const tcpDataOffset = (data[ihl + 12] >> 4) * 4;
        return data.slice(ihl + tcpDataOffset);
    }
    if ((data[0] >> 4) === 6) {
        const tcpDataOffset = (data[40 + 12] >> 4) * 4;
        return data.slice(40 + tcpDataOffset);
    }
    if (data.length >= 14) {
        const etherType = (data[12] << 8) | data[13];
        if (etherType === 0x0800 || etherType === 0x86DD) return extractTlsPayload(data.slice(14));
    }
    return null;
}

const keylog = parseKeylog(tx.forensic_evidence.keylog);
const decryptor = new TlsDecryptor();
await decryptor.initialize(keylog);

const appPackets = tx.forensic_evidence.raw_packets.packets.filter(p => p.packet_type === 'application');
const firstPkt = appPackets[0];
const rawData = base64ToBytes(firstPkt.data);
const tlsData = extractTlsPayload(rawData);

const records = parseTlsRecords(tlsData);
console.log('Records found:', records.length);
console.log('Packet tls_seq:', firstPkt.tls_seq);
console.log('Decryptor clientSeq before:', decryptor.clientSeq.toString());

// Test with different sequences
for (const testSeq of [0n, 1n, 2n]) {
  decryptor.clientSeq = testSeq;
  console.log(`\nTrying with seq=${testSeq}...`);
  try {
    const decrypted = await decryptor.decryptRecord(records[0].raw, 'client');
    console.log('SUCCESS! Plaintext length:', decrypted.plaintext.length);
    console.log('First bytes:', Buffer.from(decrypted.plaintext.slice(0, 20)).toString('hex'));
    break;
  } catch (e) {
    console.log('Failed:', e.message.substring(0, 50));
  }
}
