#!/usr/bin/env node
/**
 * Debug a transaction where request is missing
 */
import { readFileSync } from 'fs';
import { parseKeylog } from './js/validator.js';
import { parseFrames, FrameType } from './js/protocol/http2.js';
import { base64ToBytes } from './js/crypto/hash.js';
import { extractTcpSegment } from './js/protocol/tcp.js';
import { TlsDecryptor, parseTlsRecords, TLS_CONTENT_TYPE } from './js/crypto/tls.js';

const txFile = '/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl';
const lines = readFileSync(txFile, 'utf-8').trim().split('\n');

// Find a failing transaction
const targetId = process.argv[2] || '01KFJVCTB7QCVTAXVESW1YB7NF';

for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;

    if (tx.id !== targetId) continue;

    const evidence = tx.forensic_evidence;
    const streamId = evidence.h2_stream_id;

    console.log('=== Transaction:', tx.id, '===');
    console.log('URL:', tx.request?.url);
    console.log('Stream ID:', streamId);
    console.log('Original request method:', tx.request?.method);
    console.log('');

    // Parse keylog
    const keylog = parseKeylog(evidence.keylog);
    console.log('Keylog version:', keylog?.version);

    const packets = evidence.raw_packets?.packets || [];
    console.log('Total packets:', packets.length);
    console.log('  Handshake:', packets.filter(p => p.packet_type === 'handshake').length);
    console.log('  Application:', packets.filter(p => p.packet_type === 'application').length);
    console.log('  Client->Server:', packets.filter(p => p.direction === 'client_to_server').length);
    console.log('  Server->Client:', packets.filter(p => p.direction === 'server_to_client').length);
    console.log('');

    // Extract TCP segments by direction
    function getSegments(direction) {
        const segments = [];
        const seenSeqs = new Set();
        for (const pkt of packets.filter(p => p.direction === direction)) {
            const rawData = base64ToBytes(pkt.data);
            const tcp = extractTcpSegment(rawData);
            if (tcp && tcp.payload.length > 0 && !seenSeqs.has(tcp.seqNum)) {
                seenSeqs.add(tcp.seqNum);
                segments.push({ payload: tcp.payload, seq: tcp.seqNum, type: pkt.packet_type });
            }
        }
        segments.sort((a, b) => a.seq - b.seq);
        return segments;
    }

    const clientSegments = getSegments('client_to_server');
    const serverSegments = getSegments('server_to_client');

    console.log('=== Client (Request) Segments ===');
    for (const seg of clientSegments) {
        console.log(`  [${seg.type}] seq=${seg.seq} len=${seg.payload.length}`);
    }

    console.log('\n=== Server (Response) Segments ===');
    for (const seg of serverSegments) {
        console.log(`  [${seg.type}] seq=${seg.seq} len=${seg.payload.length}`);
    }

    // Concatenate
    function concat(segments) {
        const total = segments.reduce((s, seg) => s + seg.payload.length, 0);
        const result = new Uint8Array(total);
        let off = 0;
        for (const seg of segments) {
            result.set(seg.payload, off);
            off += seg.payload.length;
        }
        return result;
    }

    const clientStream = concat(clientSegments);
    const serverStream = concat(serverSegments);

    console.log('\nClient stream:', clientStream.length, 'bytes');
    console.log('Server stream:', serverStream.length, 'bytes');

    // Parse TLS records
    const clientRecords = parseTlsRecords(clientStream);
    const serverRecords = parseTlsRecords(serverStream);

    // Check for gaps
    console.log('\n=== Client Sequence Analysis ===');
    let prevEnd = null;
    for (const seg of clientSegments) {
        const gap = prevEnd !== null ? seg.seq - prevEnd : 0;
        const gapStr = gap > 0 ? ` *** GAP ${gap}b ***` : gap < 0 ? ` (overlap ${-gap}b)` : '';
        console.log(`  seq=${seg.seq} len=${seg.payload.length} [${seg.type}]${gapStr}`);
        prevEnd = seg.seq + seg.payload.length;
    }

    console.log('\n=== Client TLS Records ===');
    for (let i = 0; i < clientRecords.length; i++) {
        const r = clientRecords[i];
        const typeName = r.type === 23 ? 'APP' : r.type === 22 ? 'HS' : r.type === 20 ? 'CCS' : r.type;
        console.log(`  [${i}] type=${typeName} size=${r.data.length}`);
    }

    console.log('\n=== Server TLS Records ===');
    for (let i = 0; i < serverRecords.length; i++) {
        const r = serverRecords[i];
        const typeName = r.type === 23 ? 'APP' : r.type === 22 ? 'HS' : r.type === 20 ? 'CCS' : r.type;
        console.log(`  [${i}] type=${typeName} size=${r.data.length}`);
    }

    // Initialize decryptor and decrypt
    const decryptor = new TlsDecryptor();
    await decryptor.initialize(keylog);

    console.log('\n=== Decrypting Client Records ===');
    let clientAppSeq = 0;
    for (let i = 0; i < clientRecords.length; i++) {
        const rec = clientRecords[i];
        if (rec.type !== TLS_CONTENT_TYPE.APPLICATION_DATA) continue;

        try {
            const decrypted = await decryptor.decryptRecord(rec.raw, 'client', clientAppSeq, null, 'application');
            console.log(`  Record ${i}: ${rec.data.length}b -> ${decrypted.plaintext.length}b (seq ${decrypted.seq}, contentType=${decrypted.contentType})`);

            if (decrypted.contentType === 23) {
                // Try parsing HTTP/2 frames
                const data = decrypted.plaintext;

                // Skip connection preface if present
                let offset = 0;
                const preface = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';
                const prefaceBytes = new TextEncoder().encode(preface);
                if (data.length >= prefaceBytes.length) {
                    let isPreface = true;
                    for (let j = 0; j < prefaceBytes.length; j++) {
                        if (data[j] !== prefaceBytes[j]) { isPreface = false; break; }
                    }
                    if (isPreface) {
                        console.log(`    -> Skipped connection preface`);
                        offset = prefaceBytes.length;
                    }
                }

                const sliced = data.slice(offset);
                if (sliced.length >= 9) {
                    try {
                        const frames = parseFrames(sliced);
                        for (const frame of frames) {
                            const typeName = Object.keys(FrameType).find(k => FrameType[k] === frame.type) || frame.type;
                            const marker = frame.streamId === streamId ? ' <-- TARGET STREAM' : '';
                            console.log(`      [${typeName}] stream=${frame.streamId} flags=0x${frame.flags.toString(16)} len=${frame.payload.length}${marker}`);
                        }
                    } catch (e) {
                        console.log(`    -> Frame parse error: ${e.message}`);
                    }
                }
            }
            clientAppSeq = decrypted.seq + 1;
        } catch (e) {
            console.log(`  Record ${i}: Decrypt error: ${e.message}`);
        }
    }

    break;
}
