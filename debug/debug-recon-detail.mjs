#!/usr/bin/env node
/**
 * Debug: Detailed reconstruction debugging
 */
import { readFileSync } from 'fs';
import { parseKeylog, reconstructTransaction } from './js/validator.js';
import { parseFrames, FrameType, extractHeaderBlock } from './js/protocol/http2.js';
import { base64ToBytes } from './js/crypto/hash.js';
import { extractTcpSegment } from './js/protocol/tcp.js';
import { TlsDecryptor, parseTlsRecords, TLS_CONTENT_TYPE } from './js/crypto/tls.js';

const txFile = '/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl';
const lines = readFileSync(txFile, 'utf-8').trim().split('\n');

// Find first HTTP/2 with response where reconstruction fails
const targetId = '01KFJS2G3EEF4F6PA5ACBA3T30'; // The one from earlier debug

for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;

    if (tx.id !== targetId) continue;

    const evidence = tx.forensic_evidence;
    const streamId = evidence.h2_stream_id;

    console.log('=== Transaction:', tx.id, '===');
    console.log('URL:', tx.request?.url?.substring(0, 60));
    console.log('Stream ID:', streamId);
    console.log('');

    // Parse keylog
    const keylog = parseKeylog(evidence.keylog);
    console.log('Keylog version:', keylog?.version);

    // Manual TLS decryption
    const packets = evidence.raw_packets?.packets || [];

    // Extract TCP segments
    function getSegments(direction) {
        const segments = [];
        const seenSeqs = new Set();
        for (const pkt of packets.filter(p => p.direction === direction)) {
            const rawData = base64ToBytes(pkt.data);
            const tcp = extractTcpSegment(rawData);
            if (tcp && tcp.payload.length > 0 && !seenSeqs.has(tcp.seqNum)) {
                seenSeqs.add(tcp.seqNum);
                segments.push({ payload: tcp.payload, seq: tcp.seqNum });
            }
        }
        segments.sort((a, b) => a.seq - b.seq);
        return segments;
    }

    const clientSegments = getSegments('client_to_server');
    const serverSegments = getSegments('server_to_client');

    console.log('Client segments:', clientSegments.length);
    console.log('Server segments:', serverSegments.length);

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

    const clientRecords = parseTlsRecords(clientStream);
    const serverRecords = parseTlsRecords(serverStream);

    console.log('Client TLS records:', clientRecords.length);
    console.log('Server TLS records:', serverRecords.length);

    // Show server TLS records with their sizes
    console.log('Server TLS record sizes:');
    for (let i = 0; i < serverRecords.length; i++) {
        const r = serverRecords[i];
        const typeName = r.type === 23 ? 'APP' : r.type === 22 ? 'HS' : r.type;
        console.log(`  [${i}] type=${typeName} size=${r.data.length}`);
    }

    // Show packet details
    console.log('\\nPacket details:');
    const serverPkts = packets.filter(p => p.direction === 'server_to_client');
    for (let i = 0; i < serverPkts.length; i++) {
        const pkt = serverPkts[i];
        const rawData = base64ToBytes(pkt.data);
        const tcp = extractTcpSegment(rawData);
        console.log(`  [${i}] type=${pkt.packet_type} seq=${tcp?.seqNum || 'N/A'} payload=${tcp?.payload?.length || 0}b`);
    }

    // Check for sequence gaps
    console.log('\\nSequence analysis:');
    let prevEnd = null;
    for (const seg of serverSegments) {
        const gap = prevEnd !== null ? seg.seq - prevEnd : 0;
        const gapStr = gap > 0 ? ` *** GAP ${gap}b ***` : gap < 0 ? ` (overlap ${-gap}b)` : '';
        console.log(`  seq=${seg.seq} len=${seg.payload.length}${gapStr}`);
        prevEnd = seg.seq + seg.payload.length;
    }

    // Initialize decryptor
    const decryptor = new TlsDecryptor();
    await decryptor.initialize(keylog);

    // Decrypt all APPLICATION_DATA records
    const allPlaintext = [];

    for (const [dir, records] of [['client', clientRecords], ['server', serverRecords]]) {
        let appSeq = 0;
        let hsSeq = 0;
        for (const record of records) {
            if (record.type !== TLS_CONTENT_TYPE.APPLICATION_DATA) continue;
            try {
                const decrypted = await decryptor.decryptRecord(record.raw, dir, appSeq, null, 'application');
                appSeq = decrypted.seq + 1;
                // Check inner content type from decrypted result
                const innerType = decrypted.contentType;
                console.log(`  [${dir}] Decrypted ${record.data.length}b -> ${decrypted.plaintext.length}b, contentType=${innerType}`);
                if (innerType === 23) { // Application data
                    allPlaintext.push({ direction: dir, data: decrypted.plaintext });
                } else if (innerType === 22) {
                    console.log(`    -> TLS Handshake (post-handshake data, skipping)`);
                } else {
                    console.log(`    -> Unknown content type ${innerType}, including anyway`);
                    allPlaintext.push({ direction: dir, data: decrypted.plaintext });
                }
            } catch (e) {
                // Try handshake keys
                try {
                    const decrypted = await decryptor.decryptRecord(record.raw, dir, hsSeq, null, 'handshake');
                    hsSeq = decrypted.seq + 1;
                    console.log(`  [${dir}] Decrypted with HS keys ${decrypted.plaintext.length}b, contentType=${decrypted.contentType}`);
                    if (decrypted.contentType === 23) {
                        allPlaintext.push({ direction: dir, data: decrypted.plaintext });
                    } else {
                        console.log(`    -> TLS Handshake, skipping`);
                    }
                } catch (e2) {
                    console.log(`  Decrypt fail [${dir}]: ${e2.message}`);
                }
            }
        }
    }

    console.log('Decrypted records (after filtering):', allPlaintext.length);

    // Try to parse frames
    for (const { direction, data } of allPlaintext) {
        // Skip HTTP/2 connection preface
        let offset = 0;
        const preface = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';
        const prefaceBytes = new TextEncoder().encode(preface);
        if (data.length >= prefaceBytes.length) {
            let isPreface = true;
            for (let i = 0; i < prefaceBytes.length; i++) {
                if (data[i] !== prefaceBytes[i]) { isPreface = false; break; }
            }
            if (isPreface) {
                console.log(`  [${direction}] Skipped connection preface`);
                offset = prefaceBytes.length;
            }
        }

        const sliced = data.slice(offset);
        console.log(`  [${direction}] Parsing ${sliced.length} bytes...`);
        console.log(`    First 50 bytes: ${Array.from(sliced.slice(0, 50)).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);

        // Check if this could be continuation of previous frame
        if (sliced.length > 0 && sliced.length < 9) {
            console.log(`    -> Too short for HTTP/2 frame header (need 9 bytes)`);
        } else if (sliced.length >= 9) {
            const frameLen = (sliced[0] << 16) | (sliced[1] << 8) | sliced[2];
            const frameType = sliced[3];
            const frameFlags = sliced[4];
            const frameStream = ((sliced[5] & 0x7f) << 24) | (sliced[6] << 16) | (sliced[7] << 8) | sliced[8];
            console.log(`    Manual parse: len=${frameLen}, type=${frameType}, flags=0x${frameFlags.toString(16)}, stream=${frameStream}`);
            if (frameLen + 9 > sliced.length) {
                console.log(`    -> INCOMPLETE: need ${frameLen + 9} bytes, have ${sliced.length}`);
            }
        }

        try {
            const frames = parseFrames(sliced);
            console.log(`    Found ${frames.length} frames`);

            for (const frame of frames) {
                const typeName = Object.keys(FrameType).find(k => FrameType[k] === frame.type) || frame.type;
                const marker = frame.streamId === streamId ? ' <-- TARGET' : '';
                console.log(`      [${typeName}] stream=${frame.streamId} flags=0x${frame.flags.toString(16)} len=${frame.payload.length}${marker}`);

                if (frame.streamId === streamId && frame.type === FrameType.HEADERS) {
                    console.log(`        -> Found HEADERS for target stream!`);
                    try {
                        const headerBlock = extractHeaderBlock(frame.payload, frame.flags);
                        console.log(`        -> Header block: ${headerBlock.length} bytes`);
                    } catch (e) {
                        console.log(`        -> extractHeaderBlock failed: ${e.message}`);
                    }
                }
            }
        } catch (e) {
            console.log(`    Frame parse error: ${e.message}`);
        }
    }

    break; // Just show one
}
