#!/usr/bin/env node
import { readFileSync } from 'fs';

const lines = readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').trim().split('\n');

for (const line of lines) {
    const tx = JSON.parse(line).data;
    if (!tx || tx.protocol !== 'HTTP/2') continue;
    if (tx.forensic_evidence?.h2_stream_id === 3 && tx.request?.url?.includes('wikipedia')) {
        console.log('=== Stream 3 Transaction Evidence ===\n');
        console.log('URL:', tx.request.url);
        console.log('Stream ID:', tx.forensic_evidence.h2_stream_id);
        console.log('');

        const pkts = tx.forensic_evidence?.raw_packets?.packets || [];
        console.log('Evidence claims:');
        console.log('  handshake_count:', tx.forensic_evidence.raw_packets?.handshake_count);
        console.log('  application_count:', tx.forensic_evidence.raw_packets?.application_count);
        console.log('  total_bytes:', tx.forensic_evidence.raw_packets?.total_bytes);
        console.log('');

        console.log('Actual packets:', pkts.length);
        const byType = {};
        for (const p of pkts) {
            const key = `${p.packet_type}_${p.direction}`;
            byType[key] = (byType[key] || 0) + 1;
        }
        console.log('By type/direction:', byType);
        console.log('');

        // List application packets
        console.log('Application packets:');
        const appPkts = pkts.filter(p => p.packet_type === 'application');
        for (let i = 0; i < appPkts.length; i++) {
            const p = appPkts[i];
            const size = Buffer.from(p.data, 'base64').length;
            console.log(`  ${i}: ${p.direction} ${size}b`);
        }
        break;
    }
}
