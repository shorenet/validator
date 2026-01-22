#!/usr/bin/env node
/**
 * Debug: Investigate response hash mismatches
 */
import { readFileSync } from 'fs';
import { compareTransactionHash, reconstructTransaction, parseKeylog } from './js/validator.js';

const txFile = '/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl';
const lines = readFileSync(txFile, 'utf-8').trim().split('\n');

for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;

    if (tx.protocol !== 'HTTP/2') continue;
    if (!tx.forensic_evidence) continue;

    try {
        const result = await compareTransactionHash(tx, { verbose: false });

        // Also get reconstructed details
        const reconResult = await reconstructTransaction(tx, { verbose: false });

        if (!result.fullMatch && result.requestMatch && !result.responseMatch) {
            // Found a request-only match
            console.log('=== Transaction:', tx.id, '===');
            console.log('URL:', tx.request?.url?.substring(0, 80));
            console.log('Stream ID:', tx.forensic_evidence?.h2_stream_id);
            console.log('');

            // Check keylog
            const keylog = tx.forensic_evidence?.keylog;
            console.log('Keylog present:', !!keylog);
            console.log('Keylog length:', keylog?.length || 0);
            console.log('Keylog:');
            console.log(keylog);
            console.log('');

            // Parse keylog manually to check
            const keys = {};
            for (const line of (keylog || '').split('\n')) {
                const trimmed = line.trim();
                if (!trimmed || trimmed.startsWith('#')) continue;
                const parts = trimmed.split(/\s+/);
                if (parts.length >= 3) {
                    keys[parts[0].toLowerCase()] = true;
                }
            }
            console.log('Found keys:', Object.keys(keys));
            console.log('');

            // Check raw packets
            const packets = tx.forensic_evidence?.raw_packets?.packets || [];
            console.log('Raw packets:', packets.length);
            console.log('  Handshake:', packets.filter(p => p.packet_type === 'handshake').length);
            console.log('  Application:', packets.filter(p => p.packet_type === 'application').length);
            console.log('  Client:', packets.filter(p => p.direction === 'client_to_server').length);
            console.log('  Server:', packets.filter(p => p.direction === 'server_to_client').length);
            console.log('');

            // Check HPACK tables
            console.log('HPACK tables:');
            console.log('  hpack_request_table:', tx.forensic_evidence?.hpack_request_table ? 'present' : 'MISSING');
            console.log('  hpack_response_table:', tx.forensic_evidence?.hpack_response_table ? 'present' : 'MISSING');
            console.log('  hpack_dynamic_table:', tx.forensic_evidence?.hpack_dynamic_table ? 'present' : 'MISSING');
            console.log('');

            // List all keys in forensic_evidence
            console.log('All forensic_evidence keys:', Object.keys(tx.forensic_evidence || {}));
            console.log('');

            console.log('Original response:');
            console.log('  Status:', tx.response?.status);
            const origHeaders = tx.response?.headers || {};
            console.log('  Headers:', Object.keys(origHeaders).join(', '));
            console.log('  Body length:', tx.response?.body?.length || 0);
            console.log('');

            // Test parseKeylog directly with actual evidence
            const parsedKl = parseKeylog(tx.forensic_evidence.keylog);
            console.log('parseKeylog result:', parsedKl ? parsedKl.version : 'null');
            console.log('');

            // Call reconstructTransaction with correct args
            const evidence = tx.forensic_evidence;
            const reconResult2 = await reconstructTransaction(tx, evidence, { verbose: true });
            console.log('Reconstructed response:');
            const recon = result.reconstructed?.response;
            console.log('reconResult (correct call):', reconResult2.reconstructed?.response ? 'present' : 'null', reconResult2.error || '');
            if (recon) {
                console.log('  Status:', recon.status);
                const reconHeaders = recon.headers || {};
                console.log('  Headers:', Object.keys(reconHeaders).join(', '));
                console.log('  Body length:', recon.body?.length || 0);

                console.log('');
                console.log('Differences:');
                if (recon.status !== tx.response?.status) {
                    console.log('  Status: recon=', recon.status, 'orig=', tx.response?.status);
                }

                for (const key of Object.keys(origHeaders)) {
                    if (reconHeaders[key] !== origHeaders[key]) {
                        console.log(`  Header [${key}]: recon="${reconHeaders[key]?.substring(0, 50) || 'MISSING'}" orig="${origHeaders[key]?.substring(0, 50)}"`);
                    }
                }
                for (const key of Object.keys(reconHeaders)) {
                    if (!(key in origHeaders)) {
                        console.log(`  Header [${key}]: EXTRA in recon="${reconHeaders[key]?.substring(0, 50)}"`);
                    }
                }

                // Check body
                if (recon.body !== tx.response?.body) {
                    console.log(`  Body: different (recon ${recon.body?.length || 0}b vs orig ${tx.response?.body?.length || 0}b)`);
                }
            } else {
                console.log('  NULL');
            }

            break; // Just show one
        }
    } catch (e) {
        console.error('Error:', e.message);
    }
}
