#!/usr/bin/env node
/**
 * Check ALL server packets including handshake to find where response HEADERS might be.
 */
import { readFileSync } from 'fs';
import { compareTransactionHash, parseKeylog } from './js/validator.js';
import { base64ToBytes, bytesToHex } from './js/crypto/hash.js';
import { extractTcpSegment } from './js/protocol/tcp.js';
import { parseTlsRecords, TLS_CONTENT_TYPE } from './js/crypto/tls.js';

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

    console.log('=== Full Server Packet Analysis ===\n');
    console.log('Transaction ID:', tx.id);
    console.log('URL:', tx.request?.url);
    console.log('h2_stream_id:', evidence.h2_stream_id);
    console.log('');

    // Get ALL server packets
    const packets = evidence.raw_packets?.packets || [];
    const serverPkts = packets.filter(p => p.direction === 'server_to_client');

    // Sort by TCP seq
    const seqs = [];
    for (const pkt of serverPkts) {
        const data = base64ToBytes(pkt.data);
        const tcp = extractTcpSegment(data);
        if (tcp) {
            seqs.push({
                type: pkt.packet_type,
                seq: tcp.seqNum,
                len: tcp.payload.length,
                payload: tcp.payload
            });
        }
    }

    seqs.sort((a, b) => a.seq - b.seq);

    console.log('All server packets sorted by TCP seq:');
    for (let i = 0; i < seqs.length; i++) {
        const s = seqs[i];
        let gap = '';
        if (i > 0) {
            const prevEnd = seqs[i-1].seq + seqs[i-1].len;
            if (s.seq > prevEnd) {
                gap = ` *** GAP OF ${s.seq - prevEnd} BYTES ***`;
            }
        }

        // Check TLS structure
        let tlsInfo = '';
        if (s.payload.length >= 5) {
            const type = s.payload[0];
            const version = (s.payload[1] << 8) | s.payload[2];
            const recordLen = (s.payload[3] << 8) | s.payload[4];
            const isValidTls = type >= 20 && type <= 23 && version >= 0x0300 && version <= 0x0303;
            tlsInfo = isValidTls
                ? ` TLS: type=${type} len=${recordLen}`
                : ` NOT TLS (byte0=${type})`;
        }

        console.log(`  ${i}: [${s.type}] seq=${s.seq} len=${s.len}${tlsInfo}${gap}`);
    }

    // Check where the GAP is and what the missing packet contains
    console.log('\n=== Looking for response HEADERS ===');
    console.log('The first "application" packet doesn\'t start with valid TLS header.');
    console.log('The TLS record containing response HEADERS must have started BEFORE this packet.');
    console.log('');

    // Find where the last handshake packet ends vs where first app packet starts
    const lastHandshake = seqs.filter(s => s.type === 'handshake').pop();
    const firstApp = seqs.find(s => s.type === 'application');

    if (lastHandshake && firstApp) {
        const hsEnd = lastHandshake.seq + lastHandshake.len;
        console.log(`Last handshake ends at: ${hsEnd}`);
        console.log(`First app starts at: ${firstApp.seq}`);

        if (firstApp.seq === hsEnd) {
            console.log('No gap - first app packet continues from last handshake');
        } else if (firstApp.seq > hsEnd) {
            console.log(`GAP: ${firstApp.seq - hsEnd} bytes missing`);
        } else {
            console.log(`OVERLAP: First app packet overlaps with handshake by ${hsEnd - firstApp.seq} bytes`);
        }
    }

    // Try to concatenate ALL server packets and parse TLS records
    console.log('\n=== Concatenating ALL server packets ===');
    let totalLen = 0;
    for (const s of seqs) totalLen += s.len;

    const combined = new Uint8Array(totalLen);
    let offset = 0;
    for (const s of seqs) {
        combined.set(s.payload, offset);
        offset += s.len;
    }

    console.log(`Combined ${seqs.length} packets into ${combined.length} bytes`);

    const tlsRecords = parseTlsRecords(combined);
    console.log(`Parsed ${tlsRecords.length} TLS records`);

    for (let i = 0; i < tlsRecords.length; i++) {
        const rec = tlsRecords[i];
        const typeName = rec.type === 22 ? 'handshake' : rec.type === 23 ? 'app_data' : `type${rec.type}`;
        console.log(`  Record ${i}: ${typeName} len=${rec.data.length}`);
    }

    break;
}
