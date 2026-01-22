#!/usr/bin/env node
/**
 * Debug why response is not being reconstructed even though we have
 * hpack_response_table and server packets.
 */
import { readFileSync } from 'fs';
import { compareTransactionHash } from './js/validator.js';
import { base64ToBytes } from './js/crypto/hash.js';
import { extractTcpSegment } from './js/protocol/tcp.js';

const txFile = '/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl';
const lines = readFileSync(txFile, 'utf-8').trim().split('\n');

// Find first HTTP/2 transaction where response is missing in reconstruction
let count = 0;
for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;

    if (tx.protocol !== 'HTTP/2') continue;
    if (!tx.forensic_evidence) continue;

    const result = await compareTransactionHash(tx, { verbose: false });

    if (result.error) continue;
    if (result.fullMatch) continue;

    // Check if it's a "response missing" case
    if (result.reconstructed?.response !== null) continue;
    if (tx.response === null) continue;

    count++;
    if (count > 1) continue;

    const evidence = tx.forensic_evidence;

    console.log('=== Debug Response Missing ===\n');
    console.log('Transaction ID:', tx.id);
    console.log('URL:', tx.request?.url);
    console.log('Original response status:', tx.response?.status);
    console.log('Reconstructed response:', result.reconstructed?.response);
    console.log('');

    // Check packets
    const packets = evidence.raw_packets?.packets || [];
    const clientPkts = packets.filter(p => p.direction === 'client_to_server');
    const serverPkts = packets.filter(p => p.direction === 'server_to_client');

    console.log(`Total packets: ${packets.length}`);
    console.log(`Client packets: ${clientPkts.length}`);
    console.log(`Server packets: ${serverPkts.length}`);
    console.log('');

    // Show packet types
    const byType = {};
    for (const p of packets) {
        const key = `${p.direction}-${p.packet_type}`;
        byType[key] = (byType[key] || 0) + 1;
    }
    console.log('Packets by type:', byType);
    console.log('');

    // Check HPACK snapshots
    console.log('hpack_request_table entries:', evidence.hpack_request_table?.entries?.length || 0);
    console.log('hpack_response_table entries:', evidence.hpack_response_table?.entries?.length || 0);
    console.log('');

    // Show server app packets
    const serverApp = serverPkts.filter(p => p.packet_type === 'application');
    console.log(`Server application packets: ${serverApp.length}`);

    for (let i = 0; i < Math.min(3, serverApp.length); i++) {
        const pkt = serverApp[i];
        const data = base64ToBytes(pkt.data);
        const tcp = extractTcpSegment(data);
        console.log(`  Server pkt ${i}: size=${data.length}, TCP payload=${tcp?.payload.length || 'N/A'}`);
    }

    // Check h2_stream_id
    console.log('\nh2_stream_id:', evidence.h2_stream_id);

    break;
}

console.log(`\nTotal "response missing" cases examined: ${count}`);
