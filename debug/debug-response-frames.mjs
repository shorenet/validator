#!/usr/bin/env node
/**
 * Debug what HTTP/2 frames are in server packets.
 */
import { readFileSync } from 'fs';
import { compareTransactionHash, parseKeylog } from './js/validator.js';
import { base64ToBytes, bytesToHex } from './js/crypto/hash.js';
import { extractTcpSegment } from './js/protocol/tcp.js';
import { TlsDecryptor, parseTlsRecords, TLS_CONTENT_TYPE } from './js/crypto/tls.js';
import { parseFrames, FrameType } from './js/protocol/http2.js';

const txFile = '/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl';
const lines = readFileSync(txFile, 'utf-8').trim().split('\n');

// Find first HTTP/2 transaction where response is missing
for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;

    if (tx.protocol !== 'HTTP/2') continue;
    if (!tx.forensic_evidence) continue;

    const result = await compareTransactionHash(tx, { verbose: false });

    if (result.error) continue;
    if (result.fullMatch) continue;
    if (result.reconstructed?.response !== null) continue;
    if (tx.response === null) continue;

    const evidence = tx.forensic_evidence;

    console.log('=== Debug Response Frames ===\n');
    console.log('Transaction ID:', tx.id);
    console.log('URL:', tx.request?.url);
    console.log('h2_stream_id:', evidence.h2_stream_id);
    console.log('');

    // Get ALL server packets (including handshake)
    const packets = evidence.raw_packets?.packets || [];
    const serverPkts = packets.filter(p => p.direction === 'server_to_client');

    console.log(`Total server packets: ${serverPkts.length}`);
    console.log(`  Handshake: ${serverPkts.filter(p => p.packet_type === 'handshake').length}`);
    console.log(`  Application: ${serverPkts.filter(p => p.packet_type === 'application').length}`);
    console.log('');

    // Show TCP seq for each server packet
    console.log('All server packets (by TCP seq):');
    for (const pkt of serverPkts) {
        const data = base64ToBytes(pkt.data);
        const tcp = extractTcpSegment(data);
        console.log(`  ${pkt.packet_type}: TCP seq=${tcp?.seqNum || 'N/A'}, len=${tcp?.payload.length || 'N/A'}`);
    }
    console.log('');

    // Look at just app packets and find gaps
    const appPkts = serverPkts.filter(p => p.packet_type === 'application');
    console.log('Server application packets - TCP sequence analysis:');

    const seqs = [];
    for (const pkt of appPkts) {
        const data = base64ToBytes(pkt.data);
        const tcp = extractTcpSegment(data);
        if (tcp) {
            seqs.push({ seq: tcp.seqNum, len: tcp.payload.length, end: tcp.seqNum + tcp.payload.length });
        }
    }

    seqs.sort((a, b) => a.seq - b.seq);

    for (let i = 0; i < seqs.length; i++) {
        const s = seqs[i];
        let gap = '';
        if (i > 0) {
            const prevEnd = seqs[i-1].end;
            if (s.seq > prevEnd) {
                gap = ` *** GAP OF ${s.seq - prevEnd} BYTES ***`;
            }
        }
        console.log(`  seq=${s.seq} len=${s.len} end=${s.end}${gap}`);
    }

    console.log('\nNOTE: If the first packet doesn\'t start with valid TLS header,');
    console.log('that means we\'re missing an earlier packet that started the TLS record.');

    break;
}
