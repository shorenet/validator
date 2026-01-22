#!/usr/bin/env node
/**
 * Check which packets are source_packets vs application_packets.
 * The first N packets are handshake, then application_packets (connection init),
 * then source_packets (transaction-specific).
 */
import { readFileSync } from 'fs';
import { base64ToBytes } from './js/crypto/hash.js';
import { extractTcpSegment } from './js/protocol/tcp.js';

const lines = readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').trim().split('\n');

// Also check stream 1's packets for comparison
for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;
    if (tx.protocol !== 'HTTP/2') continue;
    if (!tx.request?.url?.includes('wikipedia.org/')) continue;

    const evidence = tx.forensic_evidence;
    const streamId = evidence?.h2_stream_id;

    console.log(`\n=== Stream ${streamId}: ${tx.request.url.substring(0, 60)}... ===`);

    const allPackets = evidence.raw_packets?.packets || [];
    const handshake = allPackets.filter(p => p.packet_type === 'handshake');
    const application = allPackets.filter(p => p.packet_type === 'application');

    console.log(`Packets: ${handshake.length} handshake, ${application.length} application`);

    // Show client application packets with seq numbers
    const clientApp = application.filter(p => p.direction === 'client_to_server');
    console.log(`\nClient application packets (${clientApp.length}):`);
    for (let i = 0; i < clientApp.length; i++) {
        const data = base64ToBytes(clientApp[i].data);
        const tcp = extractTcpSegment(data);
        console.log(`  ${i}: seq=${tcp?.seqNum || 'n/a'} payload=${tcp?.payload.length || data.length}b`);
    }
}
