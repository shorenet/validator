#!/usr/bin/env node
/**
 * Debug stream 3's packets to understand what frames they actually contain.
 */
import { readFileSync } from 'fs';

const lines = readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').trim().split('\n');

for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;
    if (tx.protocol !== 'HTTP/2') continue;

    const streamId = tx.forensic_evidence?.h2_stream_id;
    if (streamId !== 3) continue;
    if (!tx.request?.url?.includes('wikipedia')) continue;

    console.log('=== Stream 3 Transaction ===');
    console.log('URL:', tx.request.url);
    console.log('Stream ID from evidence:', streamId);
    console.log('');

    // Get HPACK snapshot info
    const reqTable = tx.forensic_evidence?.hpack_request_table;
    if (reqTable) {
        console.log('HPACK Request Table:');
        console.log('  Entries:', reqTable.entries?.length || 0);
        console.log('  Max size:', reqTable.max_size);
        console.log('  Current size:', reqTable.current_size);
        if (reqTable.entries?.length > 0) {
            console.log('  First 3 entries:');
            reqTable.entries.slice(0, 3).forEach((e, i) => {
                console.log(`    ${i}: ${e.name}: ${e.value.substring(0, 50)}${e.value.length > 50 ? '...' : ''}`);
            });
        }
    } else {
        console.log('No HPACK request table snapshot!');
    }
    console.log('');

    // Analyze packets
    const pkts = tx.forensic_evidence?.raw_packets?.packets || [];
    console.log('Total packets:', pkts.length);

    // Get application packets from client
    const clientApp = pkts.filter(p => p.packet_type === 'application' && p.direction === 'client_to_server');
    console.log('Client application packets:', clientApp.length);

    // For each client app packet, try to decode and see what HTTP/2 frames are inside
    // We'll just do a raw analysis - look for frame headers
    console.log('\nAnalyzing client application packet structure:');
    for (let i = 0; i < clientApp.length; i++) {
        const data = Buffer.from(clientApp[i].data, 'base64');
        console.log(`\nPacket ${i}: ${data.length} bytes`);

        // This is a raw TLS record - need to parse TLS first, then HTTP/2 frames
        // TLS record: type(1) + version(2) + length(2) + payload
        if (data.length >= 5) {
            const tlsType = data[0];
            const tlsVersion = (data[1] << 8) | data[2];
            const tlsLength = (data[3] << 8) | data[4];
            console.log(`  TLS: type=${tlsType === 23 ? 'app_data' : tlsType} ver=0x${tlsVersion.toString(16)} len=${tlsLength}`);
            console.log(`  Raw TLS record, needs decryption to see HTTP/2 frames`);
        }
    }

    console.log('\n');
    break;
}
