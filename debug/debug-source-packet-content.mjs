#!/usr/bin/env node
/**
 * Debug what HTTP/2 frames are in stream 3's source packet.
 */
import { readFileSync } from 'fs';
import { base64ToBytes } from './js/crypto/hash.js';
import { TlsDecryptor, parseTlsRecords, TLS_CONTENT_TYPE } from './js/crypto/tls.js';
import { parseFrames, FrameType, extractHeaderBlock } from './js/protocol/http2.js';
import { HpackDecoder } from './js/protocol/hpack.js';
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

    console.log('=== Stream 3 Source Packet Content ===\n');
    console.log('URL:', tx.request.url);
    console.log('');

    const keylog = parseKeylog(evidence.keylog);
    const allPackets = evidence.raw_packets?.packets || [];

    // The 4th client app packet should be stream 3's source_packet
    const clientApp = allPackets.filter(p => p.packet_type === 'application' && p.direction === 'client_to_server');
    console.log(`Client app packets: ${clientApp.length}`);

    // Identify which one is the source_packet (the one with different seq from first 3)
    const firstThreeSeqs = new Set();
    for (let i = 0; i < 3 && i < clientApp.length; i++) {
        const data = base64ToBytes(clientApp[i].data);
        const tcp = extractTcpSegment(data);
        if (tcp) firstThreeSeqs.add(tcp.seqNum);
    }

    console.log('First 3 packet seqs:', [...firstThreeSeqs]);

    // Find the source packet (not in first 3)
    let sourcePacket = null;
    for (let i = 0; i < clientApp.length; i++) {
        const data = base64ToBytes(clientApp[i].data);
        const tcp = extractTcpSegment(data);
        if (tcp && !firstThreeSeqs.has(tcp.seqNum)) {
            sourcePacket = { index: i, data, tcp };
            break;
        }
    }

    if (!sourcePacket) {
        console.log('No unique source packet found!');
        break;
    }

    console.log(`\nSource packet: index=${sourcePacket.index} seq=${sourcePacket.tcp.seqNum} len=${sourcePacket.tcp.payload.length}`);

    // Parse TLS record from just this packet
    const tlsRecords = parseTlsRecords(sourcePacket.tcp.payload);
    console.log(`TLS records in source packet: ${tlsRecords.length}`);

    for (let i = 0; i < tlsRecords.length; i++) {
        const rec = tlsRecords[i];
        const typeName = rec.type === 23 ? 'app_data' : rec.type === 22 ? 'handshake' : 'other';
        console.log(`  Record ${i}: type=${typeName} len=${rec.data.length}`);
    }

    // Decrypt and show frames
    console.log('\nDecrypting source packet TLS records...');
    const decryptor = new TlsDecryptor();
    await decryptor.initialize(keylog);

    // Need to know the correct sequence number for this record
    // The earlier records were seq 0, 1, 2 (the first 3 app_data records)
    // This source packet should be seq 3 if it's the 4th app_data record
    let appSeq = 3; // Assuming 3 prior app_data records

    for (const rec of tlsRecords) {
        if (rec.type !== TLS_CONTENT_TYPE.APPLICATION_DATA) continue;

        try {
            const decrypted = await decryptor.decryptRecord(rec.raw, 'client', appSeq, null, 'application');
            console.log(`  Decrypted seq ${appSeq}: ${decrypted.plaintext.length} bytes`);
            appSeq++;

            // Parse HTTP/2 frames
            try {
                const frames = parseFrames(decrypted.plaintext);
                for (const f of frames) {
                    const typeName = Object.keys(FrameType).find(k => FrameType[k] === f.type) || f.type;
                    const streamInfo = f.streamId > 0 ? ` stream=${f.streamId}` : '';
                    console.log(`    [Frame] ${typeName}${streamInfo} payload=${f.payload.length}b flags=0x${f.flags.toString(16)}`);
                }
            } catch (e) {
                console.log(`    [Frame parse error] ${e.message}`);
            }
        } catch (e) {
            console.log(`  Decrypt failed at seq ${appSeq}: ${e.message}`);
            // Try next seq
            appSeq++;
        }
    }

    break;
}
