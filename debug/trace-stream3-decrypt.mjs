#!/usr/bin/env node
/**
 * Trace exactly what HTTP/2 frames are in stream 3's decrypted packets.
 */
import { readFileSync } from 'fs';
import { base64ToBytes } from './js/crypto/hash.js';
import { TlsDecryptor, parseTlsRecords, TLS_CONTENT_TYPE } from './js/crypto/tls.js';
import { parseFrames, FrameType } from './js/protocol/http2.js';
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

    console.log('=== Stream 3 Full Decryption Trace ===\n');
    console.log('URL:', tx.request.url);
    console.log('');

    // Parse keylog
    const keylog = parseKeylog(evidence.keylog);
    console.log('Keylog version:', keylog?.version);
    console.log('');

    // Get all packets
    const allPackets = evidence.raw_packets?.packets || [];
    console.log('Packets:', allPackets.length);

    // Separate by type
    const handshake = allPackets.filter(p => p.packet_type === 'handshake');
    const application = allPackets.filter(p => p.packet_type === 'application');
    console.log('  Handshake:', handshake.length);
    console.log('  Application:', application.length);
    console.log('');

    // TCP reassembly
    console.log('TCP Reassembly:');
    const clientReassembler = new TcpStream();
    const serverReassembler = new TcpStream();
    const clientChunks = [];
    const serverChunks = [];

    for (const pkt of allPackets) {
        const data = base64ToBytes(pkt.data);
        const tcpSegment = extractTcpSegment(data);

        if (tcpSegment && tcpSegment.payload.length > 0) {
            const isClient = pkt.direction === 'client_to_server';
            const reassembler = isClient ? clientReassembler : serverReassembler;
            const chunks = isClient ? clientChunks : serverChunks;
            const reassembled = reassembler.processSegment(tcpSegment.seqNum, tcpSegment.payload);
            if (reassembled) {
                chunks.push({ data: reassembled, pktType: pkt.packet_type });
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

    const clientStream = concatenate(clientChunks.map(c => c.data));
    const serverStream = concatenate(serverChunks.map(c => c.data));
    console.log(`  Client stream: ${clientStream.length} bytes from ${clientChunks.length} chunks`);
    console.log(`  Server stream: ${serverStream.length} bytes from ${serverChunks.length} chunks`);
    console.log('');

    // Parse TLS records
    const clientRecords = parseTlsRecords(clientStream);
    const serverRecords = parseTlsRecords(serverStream);
    console.log('TLS Records:');
    console.log(`  Client: ${clientRecords.length} records`);
    for (const r of clientRecords) {
        console.log(`    type=${r.type} (${r.type === 23 ? 'app_data' : r.type === 22 ? 'handshake' : 'other'}) len=${r.data.length}`);
    }
    console.log(`  Server: ${serverRecords.length} records`);
    console.log('');

    // Decrypt
    console.log('TLS Decryption:');
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
                console.log(`  [${direction}] Decrypted ${decrypted.plaintext.length} bytes`);
            } catch (e) {
                console.log(`  [${direction}] Failed: ${e.message}`);
            }
        }
    }
    console.log('');

    // Parse HTTP/2 frames
    console.log('HTTP/2 Frames:');
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
            if (isPreface) {
                console.log(`  [${direction}] HTTP/2 Connection Preface`);
                offset = prefaceBytes.length;
            }
        }

        try {
            const frames = parseFrames(data.slice(offset));
            for (const f of frames) {
                const typeName = Object.keys(FrameType).find(k => FrameType[k] === f.type) || f.type;
                const streamInfo = f.streamId > 0 ? ` stream=${f.streamId}` : '';
                console.log(`  [${direction}] ${typeName}${streamInfo} payload=${f.payload.length}b`);
            }
        } catch (e) {
            console.log(`  [${direction}] Parse error: ${e.message}`);
        }
    }

    break;
}
