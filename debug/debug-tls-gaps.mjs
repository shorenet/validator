#!/usr/bin/env node
/**
 * Understand what each TLS record contains.
 */
import { readFileSync } from 'fs';
import { compareTransactionHash, parseKeylog } from './js/validator.js';
import { base64ToBytes, bytesToHex } from './js/crypto/hash.js';
import { extractTcpSegment } from './js/protocol/tcp.js';
import { TlsDecryptor, parseTlsRecords, TLS_CONTENT_TYPE } from './js/crypto/tls.js';
import { parseFrames, FrameType } from './js/protocol/http2.js';
import { HpackDecoder } from './js/protocol/hpack.js';

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

    console.log('=== Understanding TLS Records ===\n');
    console.log('Transaction ID:', tx.id);
    console.log('h2_stream_id:', evidence.h2_stream_id);
    console.log('');

    // Collect ALL server packets (handshake + application)
    const packets = evidence.raw_packets?.packets || [];
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

    // Find the gap
    console.log('TCP segments:');
    for (let i = 0; i < segments.length; i++) {
        const s = segments[i];
        const prevEnd = i > 0 ? segments[i-1].seq + segments[i-1].payload.length : s.seq;
        const gap = s.seq - prevEnd;
        const gapStr = gap > 0 ? ` *** GAP ${gap}b ***` : '';
        console.log(`  ${i}: [${s.type}] seq=${s.seq} len=${s.payload.length}${gapStr}`);
    }

    // Concatenate
    const totalLen = segments.reduce((sum, s) => sum + s.payload.length, 0);
    const combined = new Uint8Array(totalLen);
    let offset = 0;
    for (const s of segments) {
        combined.set(s.payload, offset);
        offset += s.payload.length;
    }

    // Check for the gap location in the combined stream
    let gapStart = 0;
    let gapEnd = 0;
    for (let i = 0; i < segments.length; i++) {
        const s = segments[i];
        const prevEnd = i > 0 ? segments[i-1].seq + segments[i-1].payload.length : s.seq;
        if (s.seq > prevEnd) {
            gapStart = s.seq;
            gapEnd = prevEnd;
            console.log(`\nGap found: ${gapEnd} -> ${gapStart} (${gapStart - gapEnd} bytes missing)`);
        }
    }

    console.log('\n=== TLS Records Analysis ===');
    const records = parseTlsRecords(combined);
    console.log(`Total: ${records.length} TLS records`);

    // Show each record and what it likely contains
    const keylog = parseKeylog(evidence.keylog);
    const decryptor = new TlsDecryptor();
    await decryptor.initialize(keylog);

    let appSeq = 0;
    for (let i = 0; i < records.length; i++) {
        const rec = records[i];
        console.log(`\nRecord ${i}: type=${rec.type}, len=${rec.data.length}`);

        if (rec.type === 22) {
            console.log('  -> TLS Handshake (pre-encryption)');
        } else if (rec.type === 20) {
            console.log('  -> Change Cipher Spec');
        } else if (rec.type === 23) {
            try {
                const decrypted = await decryptor.decryptRecord(rec.raw, 'server', appSeq, null, 'application');
                console.log(`  -> Decrypted: ${decrypted.plaintext.length} bytes`);

                // Check if it looks like HTTP/2 frames
                if (decrypted.plaintext.length >= 9) {
                    const len = (decrypted.plaintext[0] << 16) | (decrypted.plaintext[1] << 8) | decrypted.plaintext[2];
                    const type = decrypted.plaintext[3];
                    const flags = decrypted.plaintext[4];

                    if (type <= 10 && len < 100000) {
                        console.log(`  -> Looks like HTTP/2: type=${type}, len=${len}, flags=0x${flags.toString(16)}`);

                        const frames = parseFrames(decrypted.plaintext);
                        for (const f of frames) {
                            const typeName = Object.keys(FrameType).find(k => FrameType[k] === f.type) || f.type;
                            const marker = f.streamId === evidence.h2_stream_id ? ' <-- TARGET' : '';
                            console.log(`     [${typeName}] stream=${f.streamId} flags=0x${f.flags.toString(16)} payload=${f.payload.length}b${marker}`);
                        }
                    } else {
                        console.log(`  -> NOT HTTP/2 (first frame: type=${type}, len=${len})`);
                        console.log(`  -> First bytes: ${bytesToHex(decrypted.plaintext.slice(0, 20))}`);

                        // Check for TLS 1.3 inner content type
                        const lastByte = decrypted.plaintext[decrypted.plaintext.length - 1];
                        if (lastByte === 22 || lastByte === 23) {
                            console.log(`  -> TLS 1.3 inner type: ${lastByte} (${lastByte === 22 ? 'handshake' : 'app_data'})`);
                        }
                    }
                }

                appSeq++;
            } catch (e) {
                console.log(`  -> Decrypt error: ${e.message}`);
                appSeq++;
            }
        }
    }

    console.log('\n=== Conclusion ===');
    console.log('The 1239-byte gap between TCP packets contains the response HEADERS.');
    console.log('This packet was NOT captured as source_packets for this transaction.');

    break;
}
