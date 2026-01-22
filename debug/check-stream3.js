import { readFileSync } from 'fs';
const lines = readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').trim().split('\n');
for (const line of lines) {
    const tx = JSON.parse(line).data;
    if (!tx || tx.protocol !== 'HTTP/2') continue;
    if (tx.forensic_evidence?.h2_stream_id === 3 && tx.request?.url?.includes('wikipedia')) {
        const pkts = tx.forensic_evidence?.raw_packets?.packets || [];
        console.log('Stream 3 transaction found');
        console.log('URL:', tx.request.url);
        console.log('Total packets:', pkts.length);
        console.log('Handshake:', pkts.filter(p => p.packet_type === 'handshake').length);
        console.log('Application:', pkts.filter(p => p.packet_type === 'application').length);
        console.log('Client app:', pkts.filter(p => p.packet_type === 'application' && p.direction === 'client_to_server').length);

        // Show client app packet sizes
        const clientApp = pkts.filter(p => p.packet_type === 'application' && p.direction === 'client_to_server');
        console.log('\nClient app packet sizes:');
        for (const p of clientApp) {
            const size = Buffer.from(p.data, 'base64').length;
            console.log('  ' + size + ' bytes');
        }
        break;
    }
}
