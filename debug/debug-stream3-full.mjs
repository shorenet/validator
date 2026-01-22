#!/usr/bin/env node
/**
 * Full debug of stream 3 validation - trace every step.
 */
import { readFileSync } from 'fs';
import { base64ToBytes } from './js/crypto/hash.js';
import { TlsDecryptor, parseTlsRecords, TLS_CONTENT_TYPE } from './js/crypto/tls.js';
import { parseFrames, FrameType, extractHeaderBlock } from './js/protocol/http2.js';
import { HpackDecoder } from './js/protocol/hpack.js';
import { TcpStream, extractTcpSegment } from './js/protocol/tcp.js';
import { parseKeylog, extractTlsPayload } from './js/validator.js';

const lines = readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').trim().split('\n');

for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;
    if (tx.protocol !== 'HTTP/2') continue;

    const evidence = tx.forensic_evidence;
    const streamId = evidence?.h2_stream_id;
    if (streamId !== 3) continue;
    if (!tx.request?.url?.includes('wikipedia')) continue;

    console.log('=== Stream 3 Full Debug ===');
    console.log('URL:', tx.request.url);
    console.log('Stream ID:', streamId);
    console.log('');

    // Step 1: Parse keylog
    const keylog = parseKeylog(evidence.keylog);
    console.log('1. Keylog version:', keylog?.version);

    // Step 2: TCP reassembly
    const allPackets = evidence.raw_packets?.packets || [];
    const clientReassembler = new TcpStream();
    const serverReassembler = new TcpStream();
    const clientChunks = [];
    const serverChunks = [];

    console.log('');
    console.log('2. TCP Reassembly:');
    for (let i = 0; i < allPackets.length; i++) {
        const pkt = allPackets[i];
        const data = base64ToBytes(pkt.data);
        const tcpSegment = extractTcpSegment(data);

        if (pkt.packet_type === 'application') {
            console.log(`  Pkt ${i}: ${pkt.direction} ${pkt.packet_type} ${data.length}b -> TCP payload ${tcpSegment?.payload.length || 0}b seq=${tcpSegment?.seqNum || 'n/a'}`);
        }

        if (tcpSegment && tcpSegment.payload.length > 0) {
            const isClient = pkt.direction === 'client_to_server';
            const reassembler = isClient ? clientReassembler : serverReassembler;
            const chunks = isClient ? clientChunks : serverChunks;
            const reassembled = reassembler.processSegment(tcpSegment.seqNum, tcpSegment.payload);
            if (reassembled) chunks.push(reassembled);
        }
    }

    // Concatenate
    function concatenate(arrays) {
        const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
        const result = new Uint8Array(totalLength);
        let offset = 0;
        for (const arr of arrays) { result.set(arr, offset); offset += arr.length; }
        return result;
    }

    const clientStream = clientChunks.length > 0 ? concatenate(clientChunks) : new Uint8Array(0);
    const serverStream = serverChunks.length > 0 ? concatenate(serverChunks) : new Uint8Array(0);
    console.log(`  -> Client stream: ${clientStream.length} bytes`);
    console.log(`  -> Server stream: ${serverStream.length} bytes`);

    // Step 3: Parse TLS records
    const clientRecords = parseTlsRecords(clientStream);
    const serverRecords = parseTlsRecords(serverStream);
    console.log('');
    console.log('3. TLS Records:');
    console.log(`  Client: ${clientRecords.length} records`);
    console.log(`  Server: ${serverRecords.length} records`);

    // Count application data records
    const clientAppRecords = clientRecords.filter(r => r.type === TLS_CONTENT_TYPE.APPLICATION_DATA);
    const serverAppRecords = serverRecords.filter(r => r.type === TLS_CONTENT_TYPE.APPLICATION_DATA);
    console.log(`  Client app data: ${clientAppRecords.length}`);
    console.log(`  Server app data: ${serverAppRecords.length}`);

    // Step 4: Decrypt
    console.log('');
    console.log('4. TLS Decryption:');
    const decryptor = new TlsDecryptor();
    await decryptor.initialize(keylog);

    const allPlaintext = [];
    for (const [direction, records] of [['client', clientRecords], ['server', serverRecords]]) {
        let appSeq = 0;
        for (const record of records) {
            if (record.type !== TLS_CONTENT_TYPE.APPLICATION_DATA) continue;
            try {
                const decrypted = await decryptor.decryptRecord(record.raw, direction, appSeq, null, 'application');
                appSeq = decrypted.seq + 1;
                allPlaintext.push({ direction, data: decrypted.plaintext });
            } catch (e) {
                // try handshake keys silently
            }
        }
    }
    console.log(`  -> Decrypted ${allPlaintext.length} chunks`);
    console.log(`  -> Client chunks: ${allPlaintext.filter(p => p.direction === 'client').length}`);
    console.log(`  -> Server chunks: ${allPlaintext.filter(p => p.direction === 'server').length}`);

    // Step 5: Parse HTTP/2 frames and find HEADERS
    console.log('');
    console.log('5. HTTP/2 Frames:');

    let allFrames = [];
    for (const { direction, data } of allPlaintext) {
        // Skip preface
        let offset = 0;
        const preface = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';
        const prefaceBytes = new TextEncoder().encode(preface);
        if (data.length >= prefaceBytes.length) {
            let isPreface = true;
            for (let i = 0; i < prefaceBytes.length; i++) {
                if (data[i] !== prefaceBytes[i]) { isPreface = false; break; }
            }
            if (isPreface) offset = prefaceBytes.length;
        }

        try {
            const frames = parseFrames(data.slice(offset));
            for (const f of frames) {
                allFrames.push({ direction, ...f });
            }
        } catch (e) {
            console.log(`  Frame parse error (${direction}): ${e.message}`);
        }
    }

    // Show HEADERS frames
    const headersFrames = allFrames.filter(f => f.type === FrameType.HEADERS);
    console.log(`  Total frames: ${allFrames.length}`);
    console.log(`  HEADERS frames: ${headersFrames.length}`);
    console.log('');
    console.log('  HEADERS frames by stream:');
    for (const f of headersFrames) {
        console.log(`    Stream ${f.streamId}: ${f.direction}, payload ${f.payload.length}b`);
    }

    // Find target stream
    const targetHeaders = headersFrames.filter(f => f.streamId === streamId);
    console.log('');
    console.log(`  Target stream ${streamId} HEADERS: ${targetHeaders.length}`);

    if (targetHeaders.length === 0) {
        console.log('  *** NO HEADERS FRAME FOR TARGET STREAM! ***');

        // Show which streams ARE present
        const streamIds = new Set(allFrames.map(f => f.streamId));
        console.log(`  Streams present: ${[...streamIds].sort((a,b) => a-b).join(', ')}`);
    }

    break;
}
