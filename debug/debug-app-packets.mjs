#!/usr/bin/env node
/**
 * Debug: Check if application_packets now contains ALL packets
 */
import { readFileSync } from 'fs';
import { base64ToBytes } from './js/crypto/hash.js';
import { extractTcpSegment } from './js/protocol/tcp.js';

const txFile = '/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl';
const lines = readFileSync(txFile, 'utf-8').trim().split('\n');

// Find first HTTP/2 transaction with response missing
for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;

    if (tx.protocol !== 'HTTP/2') continue;
    if (!tx.forensic_evidence) continue;
    if (tx.response === null) continue;

    const evidence = tx.forensic_evidence;
    const packets = evidence.raw_packets?.packets || [];
    const serverPkts = packets.filter(p => p.direction === 'server_to_client');

    if (serverPkts.length < 2) continue;

    // Check for gaps in server packets
    const segments = [];
    const seenSeqs = new Set();
    for (const pkt of serverPkts) {
        const data = base64ToBytes(pkt.data);
        const tcp = extractTcpSegment(data);
        if (tcp && tcp.payload.length > 0 && !seenSeqs.has(tcp.seqNum)) {
            seenSeqs.add(tcp.seqNum);
            segments.push({ payload: tcp.payload, seq: tcp.seqNum, type: pkt.packet_type });
        }
    }
    segments.sort((a, b) => a.seq - b.seq);

    // Check for gaps
    let hasGap = false;
    for (let i = 1; i < segments.length; i++) {
        const prev = segments[i-1];
        const curr = segments[i];
        const expectedSeq = prev.seq + prev.payload.length;
        if (curr.seq > expectedSeq) {
            hasGap = true;
            console.log('=== Found gap ===');
            console.log('Transaction ID:', tx.id);
            console.log('h2_stream_id:', evidence.h2_stream_id);
            console.log(`Gap: ${expectedSeq} -> ${curr.seq} (${curr.seq - expectedSeq} bytes missing)`);
            console.log('');
            console.log('Segments:');
            for (const s of segments) {
                console.log(`  [${s.type}] seq=${s.seq} len=${s.payload.length}`);
            }
            break;
        }
    }

    if (hasGap) {
        console.log('\nThis means the packet with response HEADERS is still missing from evidence.');
        break;
    }
}

console.log('\nDone checking for gaps.');
