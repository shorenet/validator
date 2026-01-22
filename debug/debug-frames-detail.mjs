#!/usr/bin/env node
/**
 * Debug: Show frames in server TLS records for a failing transaction
 */
import { readFileSync } from 'fs';
import { compareTransactionHash } from './js/validator.js';
import { base64ToBytes, bytesToHex } from './js/crypto/hash.js';
import { extractTcpSegment } from './js/protocol/tcp.js';
import { TlsDecryptor, parseTlsRecords, TLS_CONTENT_TYPE } from './js/crypto/tls.js';
import { parseFrames, FrameType } from './js/protocol/http2.js';
import { parseKeylog } from './js/validator.js';

const txFile = '/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl';
const lines = readFileSync(txFile, 'utf-8').trim().split('\n');

// Find failing transaction
for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;

    if (tx.id !== '01KFJQS4GNRHP0DW3799QEP58X') continue;

    const evidence = tx.forensic_evidence;
    const packets = evidence.raw_packets?.packets || [];

    console.log('=== Transaction ===');
    console.log('ID:', tx.id);
    console.log('URL:', tx.request?.url);
    console.log('Stream ID:', evidence.h2_stream_id);
    console.log('Expected response status:', tx.response?.status);
    console.log('');

    // Collect server segments
    const serverPkts = packets.filter(p => p.direction === 'server_to_client');
    const segments = [];
    const seenSeqs = new Set();

    for (const pkt of serverPkts) {
        const data = base64ToBytes(pkt.data);
        const tcp = extractTcpSegment(data);
        if (tcp && tcp.payload.length > 0 && !seenSeqs.has(tcp.seqNum)) {
            seenSeqs.add(tcp.seqNum);
            segments.push({ payload: tcp.payload, seq: tcp.seqNum, type: pkt.packet_type });
        }
    }
    segments.sort((a, b) => a.seq - b.seq);

    console.log('=== Server TCP Segments ===');
    let prevEnd = null;
    for (const s of segments) {
        const gap = prevEnd !== null ? s.seq - prevEnd : 0;
        const gapStr = gap > 0 ? ` *** GAP ${gap}b ***` : '';
        console.log(`  [${s.type}] seq=${s.seq} len=${s.len || s.payload.length}${gapStr}`);
        prevEnd = s.seq + s.payload.length;
    }

    // Concatenate
    const totalLen = segments.reduce((sum, s) => sum + s.payload.length, 0);
    const combined = new Uint8Array(totalLen);
    let offset = 0;
    for (const s of segments) {
        combined.set(s.payload, offset);
        offset += s.payload.length;
    }

    console.log('\n=== TLS Records ===');
    const records = parseTlsRecords(combined);
    console.log(`Parsed ${records.length} TLS records`);

    // Initialize decryptor
    const keylog = parseKeylog(evidence.keylog);
    const decryptor = new TlsDecryptor();
    await decryptor.initialize(keylog);

    let appSeq = 0;
    for (let i = 0; i < records.length; i++) {
        const rec = records[i];
        const typeName = TLS_CONTENT_TYPE[rec.type] || rec.type;
        console.log(`\nRecord ${i}: type=${typeName} len=${rec.data.length}`);

        if (rec.type !== TLS_CONTENT_TYPE.APPLICATION_DATA) continue;

        try {
            const decrypted = await decryptor.decryptRecord(rec.raw, 'server', appSeq, null, 'application');
            console.log(`  Decrypted: ${decrypted.plaintext.length} bytes (seq ${appSeq})`);

            // Try parsing as HTTP/2 frames
            console.log(`  First 20 bytes: ${bytesToHex(decrypted.plaintext.slice(0, 20))}`);
            if (decrypted.plaintext.length >= 9) {
                const frameLen = (decrypted.plaintext[0] << 16) | (decrypted.plaintext[1] << 8) | decrypted.plaintext[2];
                const frameType = decrypted.plaintext[3];
                const frameFlags = decrypted.plaintext[4];
                const frameStreamId = ((decrypted.plaintext[5] & 0x7f) << 24) | (decrypted.plaintext[6] << 16) | (decrypted.plaintext[7] << 8) | decrypted.plaintext[8];
                console.log(`  First frame header: len=${frameLen} type=${frameType} flags=0x${frameFlags.toString(16)} stream=${frameStreamId}`);

                // Check if this looks like valid HTTP/2
                if (frameType <= 10 && frameLen < 100000 && frameLen + 9 <= decrypted.plaintext.length) {
                    const frames = parseFrames(decrypted.plaintext);
                    for (const f of frames) {
                        const typeName = Object.keys(FrameType).find(k => FrameType[k] === f.type) || f.type;
                        const marker = f.streamId === evidence.h2_stream_id ? ' <-- TARGET' : '';
                        console.log(`    [${typeName}] stream=${f.streamId} flags=0x${f.flags.toString(16)} payload=${f.payload.length}b${marker}`);
                    }
                } else {
                    console.log(`  NOT valid HTTP/2 (type=${frameType} len=${frameLen})`);
                }
            }

            appSeq++;
        } catch (e) {
            console.log(`  Decrypt error: ${e.message}`);
            appSeq++;
        }
    }

    break;
}
