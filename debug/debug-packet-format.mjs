#!/usr/bin/env node
/**
 * Debug the packet format to understand why parsing might fail.
 */
import { readFileSync } from 'fs';
import { extractTcpSegment } from './js/protocol/tcp.js';

const lines = readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').trim().split('\n');

for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;
    if (tx.protocol !== 'HTTP/2') continue;

    const streamId = tx.forensic_evidence?.h2_stream_id;
    if (streamId !== 3) continue;
    if (!tx.request?.url?.includes('wikipedia')) continue;

    const pkts = tx.forensic_evidence?.raw_packets?.packets || [];
    const clientApp = pkts.filter(p => p.packet_type === 'application' && p.direction === 'client_to_server');

    console.log('=== Stream 3 Client Application Packets ===\n');

    for (let i = 0; i < Math.min(3, clientApp.length); i++) {
        const data = Buffer.from(clientApp[i].data, 'base64');
        console.log(`Packet ${i}: ${data.length} bytes`);
        console.log(`  First 20 bytes (hex): ${data.slice(0, 20).toString('hex')}`);
        console.log(`  First byte: 0x${data[0].toString(16)} (${data[0]})`);
        console.log(`  Version nibble: ${data[0] >> 4}`);

        if ((data[0] >> 4) === 4) {
            const ihl = (data[0] & 0x0f) * 4;
            const protocol = data[9];
            console.log(`  IPv4: IHL=${ihl}, Protocol=${protocol} (${protocol === 6 ? 'TCP' : 'other'})`);

            if (protocol === 6 && data.length >= ihl) {
                const tcpData = data.slice(ihl);
                const srcPort = (tcpData[0] << 8) | tcpData[1];
                const dstPort = (tcpData[2] << 8) | tcpData[3];
                const seqNum = (tcpData[4] << 24) | (tcpData[5] << 16) | (tcpData[6] << 8) | tcpData[7];
                const dataOffset = (tcpData[12] >> 4) * 4;
                console.log(`  TCP: src=${srcPort}, dst=${dstPort}, seq=${seqNum >>> 0}, dataOffset=${dataOffset}`);

                const payload = tcpData.slice(dataOffset);
                console.log(`  TCP payload: ${payload.length} bytes`);
                console.log(`  Payload first 10 bytes: ${payload.slice(0, 10).toString('hex')}`);

                // Check TLS
                if (payload.length >= 5) {
                    const tlsType = payload[0];
                    const tlsVersion = (payload[1] << 8) | payload[2];
                    const tlsLen = (payload[3] << 8) | payload[4];
                    console.log(`  TLS: type=${tlsType} (${tlsType === 23 ? 'app_data' : tlsType === 22 ? 'handshake' : 'other'}), ver=0x${tlsVersion.toString(16)}, len=${tlsLen}`);
                }
            }
        }

        // Try extractTcpSegment
        const tcpSeg = extractTcpSegment(new Uint8Array(data));
        if (tcpSeg) {
            console.log(`  extractTcpSegment: seqNum=${tcpSeg.seqNum}, payload=${tcpSeg.payload.length} bytes`);
        } else {
            console.log(`  extractTcpSegment: FAILED to parse`);
        }

        console.log('');
    }

    break;
}
