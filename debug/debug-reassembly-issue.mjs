#!/usr/bin/env node
/**
 * Debug why the full reassembly doesn't find stream 3's HEADERS.
 */
import { readFileSync } from 'fs';
import { base64ToBytes } from './js/crypto/hash.js';
import { TlsDecryptor, parseTlsRecords, TLS_CONTENT_TYPE } from './js/crypto/tls.js';
import { TcpStream, extractTcpSegment } from './js/protocol/tcp.js';
import { parseKeylog } from './js/validator.js';

const lines = readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').trim().split('\n');

for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;
    if (tx.protocol !== 'HTTP/2') continue;

    const evidence = tx.forensic_evidence;
    const streamId = evidence?.h2_stream_id;
    if (streamId !== 3) continue;
    if (!tx.request?.url?.includes('wikipedia')) continue;

    console.log('=== Debugging TCP Reassembly for Stream 3 ===\n');

    const allPackets = evidence.raw_packets?.packets || [];
    const clientApp = allPackets.filter(p => p.packet_type === 'application' && p.direction === 'client_to_server');

    console.log('Client app packets TCP info:');
    for (let i = 0; i < clientApp.length; i++) {
        const data = base64ToBytes(clientApp[i].data);
        const tcp = extractTcpSegment(data);
        console.log(`  ${i}: seq=${tcp?.seqNum} len=${tcp?.payload.length}`);
    }

    // Show raw TCP reassembly
    console.log('\nTCP Reassembly trace:');
    const reassembler = new TcpStream();
    const chunks = [];

    for (let i = 0; i < clientApp.length; i++) {
        const data = base64ToBytes(clientApp[i].data);
        const tcp = extractTcpSegment(data);
        if (!tcp || tcp.payload.length === 0) continue;

        console.log(`  Processing pkt ${i}: seq=${tcp.seqNum} len=${tcp.payload.length}`);
        console.log(`    reassembler.nextSeq before: ${reassembler.nextSeq}`);

        const result = reassembler.processSegment(tcp.seqNum, tcp.payload);

        console.log(`    reassembler.nextSeq after: ${reassembler.nextSeq}`);
        if (result) {
            chunks.push(result);
            console.log(`    -> Produced chunk: ${result.length} bytes`);
        } else {
            console.log(`    -> No chunk (buffered or dropped)`);
        }
    }

    console.log(`\nTotal chunks: ${chunks.length}`);
    let totalBytes = 0;
    for (const c of chunks) totalBytes += c.length;
    console.log(`Total reassembled bytes: ${totalBytes}`);

    // Check stats
    const stats = reassembler.getStats();
    console.log(`Reassembly stats:`, stats);

    break;
}
