#!/usr/bin/env node
/**
 * Trace which HTTP/2 frames are in which TLS record/packet.
 * This helps identify if multiple HEADERS frames are bundled together.
 */
import { readFileSync } from 'fs';
import { base64ToBytes } from './js/crypto/hash.js';
import { TlsDecryptor, parseTlsRecords, TLS_CONTENT_TYPE } from './js/crypto/tls.js';
import { parseFrames, FrameType } from './js/protocol/http2.js';
import { TcpStream, extractTcpSegment } from './js/protocol/tcp.js';
import { parseKeylog } from './js/validator.js';

const lines = readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').trim().split('\n');

// Get stream 1's evidence (same connection as stream 3)
for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;
    if (tx.protocol !== 'HTTP/2') continue;

    const evidence = tx.forensic_evidence;
    const streamId = evidence?.h2_stream_id;
    if (streamId !== 1) continue;
    if (!tx.request?.url?.includes('www.wikipedia.org/')) continue;

    console.log('=== Stream 1 (Wikipedia main page) - Tracing All Frames Per TLS Record ===\n');
    console.log('URL:', tx.request.url);
    console.log('');

    const keylog = parseKeylog(evidence.keylog);
    const allPackets = evidence.raw_packets?.packets || [];

    // Separate into client/server and reassemble
    const clientReassembler = new TcpStream();
    const clientChunks = [];

    for (const pkt of allPackets) {
        const data = base64ToBytes(pkt.data);
        const tcp = extractTcpSegment(data);
        if (tcp && tcp.payload.length > 0 && pkt.direction === 'client_to_server') {
            const reassembled = clientReassembler.processSegment(tcp.seqNum, tcp.payload);
            if (reassembled) {
                clientChunks.push(reassembled);
            }
        }
    }

    function concatenate(arrays) {
        const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
        const result = new Uint8Array(totalLength);
        let offset = 0;
        for (const arr of arrays) { result.set(arr, offset); offset += arr.length; }
        return result;
    }

    const clientStream = concatenate(clientChunks);
    console.log(`Client stream: ${clientStream.length} bytes`);

    // Parse and decrypt TLS records one by one
    const clientRecords = parseTlsRecords(clientStream);
    console.log(`Client TLS records: ${clientRecords.length}`);
    console.log('');

    const decryptor = new TlsDecryptor();
    await decryptor.initialize(keylog);

    let appSeq = 0;
    for (let i = 0; i < clientRecords.length; i++) {
        const record = clientRecords[i];
        const typeName = record.type === 23 ? 'app_data' : record.type === 22 ? 'handshake' : record.type === 20 ? 'change_cipher' : 'other';
        console.log(`\nRecord ${i}: type=${typeName} size=${record.data.length}`);

        if (record.type !== TLS_CONTENT_TYPE.APPLICATION_DATA) continue;

        try {
            const decrypted = await decryptor.decryptRecord(record.raw, 'client', appSeq, null, 'application');
            appSeq = decrypted.seq + 1;

            console.log(`  Decrypted: ${decrypted.plaintext.length} bytes`);

            // Check for preface
            let offset = 0;
            const preface = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';
            const prefaceBytes = new TextEncoder().encode(preface);
            if (decrypted.plaintext.length >= prefaceBytes.length) {
                let isPreface = true;
                for (let j = 0; j < prefaceBytes.length; j++) {
                    if (decrypted.plaintext[j] !== prefaceBytes[j]) { isPreface = false; break; }
                }
                if (isPreface) {
                    console.log(`  [Preface]`);
                    offset = prefaceBytes.length;
                }
            }

            // Parse frames
            try {
                const frames = parseFrames(decrypted.plaintext.slice(offset));
                for (const f of frames) {
                    const typeName = Object.keys(FrameType).find(k => FrameType[k] === f.type) || f.type;
                    const streamInfo = f.streamId > 0 ? ` stream=${f.streamId}` : '';
                    console.log(`  [Frame] ${typeName}${streamInfo} payload=${f.payload.length}b flags=0x${f.flags.toString(16)}`);
                }
            } catch (e) {
                console.log(`  [Frame parse error] ${e.message}`);
            }
        } catch (e) {
            console.log(`  Decrypt failed: ${e.message}`);
        }
    }

    break;
}
