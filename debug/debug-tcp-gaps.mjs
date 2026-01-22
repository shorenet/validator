#!/usr/bin/env node
/**
 * Debug TCP sequence gaps to understand why packets are missing.
 */
import { readFileSync } from 'fs';
import { base64ToBytes } from './js/crypto/hash.js';
import { extractTcpSegment } from './js/protocol/tcp.js';

const lines = readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').trim().split('\n');

for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;
    if (tx.protocol !== 'HTTP/2') continue;

    const evidence = tx.forensic_evidence;
    const streamId = evidence?.h2_stream_id;
    if (streamId !== 3) continue;
    if (!tx.request?.url?.includes('wikipedia')) continue;

    console.log('=== Stream 3 TCP Sequence Analysis ===\n');

    const allPackets = evidence.raw_packets?.packets || [];
    const clientApp = allPackets.filter(p => p.packet_type === 'application' && p.direction === 'client_to_server');

    console.log('Client application packets:');
    let prevEnd = null;
    for (let i = 0; i < clientApp.length; i++) {
        const data = base64ToBytes(clientApp[i].data);
        const tcp = extractTcpSegment(data);
        if (!tcp) continue;

        const start = tcp.seqNum;
        const end = (tcp.seqNum + tcp.payload.length) >>> 0;

        let gapInfo = '';
        if (prevEnd !== null) {
            const gap = (start - prevEnd) >>> 0;
            if (gap > 0 && gap < 0x80000000) {
                gapInfo = ` *** GAP: ${gap} bytes ***`;
            } else if (gap !== 0) {
                // Negative gap = overlap/retransmit
                const overlap = (prevEnd - start) >>> 0;
                if (overlap < 0x80000000) {
                    gapInfo = ` (overlap: ${overlap} bytes)`;
                }
            }
        }

        console.log(`  ${i}: seq=${start} len=${tcp.payload.length} end=${end}${gapInfo}`);
        prevEnd = end;
    }

    // Total bytes in client stream
    const totalPayload = clientApp.reduce((sum, p) => {
        const data = base64ToBytes(p.data);
        const tcp = extractTcpSegment(data);
        return sum + (tcp?.payload.length || 0);
    }, 0);
    console.log(`\nTotal client payload: ${totalPayload} bytes`);

    break;
}
