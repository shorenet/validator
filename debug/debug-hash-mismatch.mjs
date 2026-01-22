#!/usr/bin/env node
/**
 * Debug hash mismatch - show what's different between original and reconstructed.
 */
import { readFileSync } from 'fs';
import { compareTransactionHash, stableStringify } from './js/validator.js';

const txFile = '/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl';
const lines = readFileSync(txFile, 'utf-8').trim().split('\n');

// Find first HTTP/2 transaction with MISMATCH
let count = 0;
for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;

    if (tx.protocol !== 'HTTP/2') continue;
    if (!tx.forensic_evidence) continue;

    // Try hash comparison
    const result = await compareTransactionHash(tx, { verbose: false });

    if (result.error) continue;
    if (result.match) continue; // Skip matches

    count++;
    if (count > 1) continue; // Only show first mismatch

    console.log('=== Debug Hash Mismatch ===\n');
    console.log('Transaction ID:', tx.id);
    console.log('URL:', tx.request?.url);
    console.log('');

    // Build original normalized (same as in compareTransactionHash)
    const evidence = tx.forensic_evidence;
    const certInfo = evidence.certificate_info || null;
    const original = {
        id: tx.id,
        protocol: tx.protocol,
        connection: tx.connection ? {
            id: tx.connection.id,
            client_addr: tx.connection.client_addr,
            server_addr: tx.connection.server_addr,
        } : null,
        request: tx.request ? {
            method: tx.request.method,
            url: tx.request.url,
            headers: normalizeHeaders(tx.request.headers),
        } : null,
        response: tx.response ? {
            status: tx.response.status,
            headers: normalizeHeaders(tx.response.headers),
        } : null,
        certificate_info: certInfo ? {
            sni: certInfo.sni,
            tls_version: certInfo.tls_version,
            alpn: certInfo.alpn,
            cipher_suite: certInfo.cipher_suite,
            certificate_chain: certInfo.certificate_chain,
        } : null,
    };

    // Serialize both and compare byte by byte
    const origJson = stableStringify(original);
    const recJson = stableStringify(result.reconstructed);

    console.log('Original JSON length:', origJson.length);
    console.log('Reconstructed JSON length:', recJson.length);
    console.log('');

    // Find first diff
    for (let i = 0; i < Math.max(origJson.length, recJson.length); i++) {
        if (origJson[i] !== recJson[i]) {
            const start = Math.max(0, i - 50);
            const end = Math.min(origJson.length, recJson.length, i + 50);
            console.log(`First diff at position ${i}:`);
            console.log(`  Original:      ...${origJson.substring(start, i)}[${origJson[i]}]${origJson.substring(i+1, end)}...`);
            console.log(`  Reconstructed: ...${recJson.substring(start, i)}[${recJson[i]}]${recJson.substring(i+1, end)}...`);
            break;
        }
    }

    // Also show request headers comparison
    console.log('\n=== Request Headers ===');
    console.log('Original headers:', Object.keys(original.request?.headers || {}).sort());
    console.log('Reconstructed headers:', Object.keys(result.reconstructed?.request?.headers || {}).sort());

    break;
}

console.log(`\nTotal mismatches: ${count}`);

function normalizeHeaders(headers) {
    if (!headers) return {};
    const normalized = {};
    for (const [name, value] of Object.entries(headers)) {
        if (name.startsWith(':')) continue;
        normalized[name.toLowerCase()] = value;
    }
    return normalized;
}
