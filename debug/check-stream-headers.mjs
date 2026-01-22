#!/usr/bin/env node
/**
 * Check if HEADERS frames for each stream are in the captured packets.
 * This helps identify if Keel is correctly capturing per-stream packets.
 */
import { readFileSync } from 'fs';
import { webcrypto } from 'crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;
import { validate } from './js/validator.js';

const lines = readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').trim().split('\n');

let fullCount = 0;
let decryptCount = 0;
let totalH2 = 0;

// Count how many have HEADERS in packets
for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;
    if (tx.protocol !== 'HTTP/2') continue;
    totalH2++;

    const result = await validate(wrapper, { verbose: false });
    if (result.level === 'full') fullCount++;
    else if (result.level === 'decrypt') decryptCount++;
}

console.log(`HTTP/2 transactions: ${totalH2}`);
console.log(`  Full (has HEADERS): ${fullCount} (${(fullCount/totalH2*100).toFixed(1)}%)`);
console.log(`  Decrypt (no HEADERS): ${decryptCount} (${(decryptCount/totalH2*100).toFixed(1)}%)`);
console.log('');
console.log(`Only ${fullCount} of ${totalH2} HTTP/2 transactions have their HEADERS frame captured.`);
console.log('The rest have packets but the HEADERS frame for their specific stream is missing.');
