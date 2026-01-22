#!/usr/bin/env node
/**
 * Debug: Show detailed packet info for a transaction with missing response
 */
import { readFileSync } from 'fs';
import { base64ToBytes } from './js/crypto/hash.js';
import { extractTcpSegment } from './js/protocol/tcp.js';
import { parseTlsRecords, TLS_CONTENT_TYPE } from './js/crypto/tls.js';

const txFile = '/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl';
const lines = readFileSync(txFile, 'utf-8').trim().split('\n');

// Find first HTTP/2 transaction with response
for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;

    if (tx.protocol !== 'HTTP/2') continue;
    if (!tx.forensic_evidence) continue;
    if (tx.response === null) continue;

    const evidence = tx.forensic_evidence;
    const packets = evidence.raw_packets?.packets || [];

    console.log('=== Transaction ===');
    console.log('ID:', tx.id);
    console.log('URL:', tx.request?.url);
    console.log('Stream ID:', evidence.h2_stream_id);
    console.log('Response status:', tx.response?.status);
    console.log('');

    console.log('=== Raw Packets ===');
    console.log(`Total: ${packets.length} packets`);
    console.log(`  Handshake: ${packets.filter(p => p.packet_type === 'handshake').length}`);
    console.log(`  Application: ${packets.filter(p => p.packet_type === 'application').length}`);
    console.log('');

    // Analyze server packets
    const serverPkts = packets.filter(p => p.direction === 'server_to_client');
    console.log('=== Server Packets ===');
    console.log(`Count: ${serverPkts.length}`);

    const segments = [];
    for (const pkt of serverPkts) {
        const data = base64ToBytes(pkt.data);
        const tcp = extractTcpSegment(data);
        if (tcp && tcp.payload.length > 0) {
            segments.push({
                seq: tcp.seqNum,
                len: tcp.payload.length,
                type: pkt.packet_type,
                payload: tcp.payload
            });
        }
    }
    segments.sort((a, b) => a.seq - b.seq);

    console.log('\nTCP segments (sorted by seq):');
    let prevEnd = null;
    for (const s of segments) {
        const gap = prevEnd !== null ? s.seq - prevEnd : 0;
        const gapStr = gap > 0 ? ` *** GAP ${gap}b ***` : '';
        console.log(`  [${s.type}] seq=${s.seq} len=${s.len}${gapStr}`);
        prevEnd = s.seq + s.len;
    }

    // Concatenate and check for TLS records
    const totalLen = segments.reduce((sum, s) => sum + s.len, 0);
    const combined = new Uint8Array(totalLen);
    let offset = 0;
    for (const s of segments) {
        combined.set(s.payload, offset);
        offset += s.payload.length;
    }

    console.log('\n=== TLS Records (from concatenated stream) ===');
    console.log(`Stream length: ${combined.length} bytes`);

    const records = parseTlsRecords(combined);
    console.log(`Parsed: ${records.length} TLS records`);
    for (let i = 0; i < records.length; i++) {
        const r = records[i];
        const typeName = TLS_CONTENT_TYPE[r.type] || r.type;
        console.log(`  Record ${i}: type=${typeName} len=${r.data.length}`);
    }

    break;
}
