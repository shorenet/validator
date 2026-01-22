#!/usr/bin/env node
/**
 * Test transaction hash comparison feature.
 *
 * For forensic validation, we need BOTH request AND response to match.
 * A transaction is only "fully validated" when the entire thing can be
 * reconstructed from evidence.
 */
import { readFileSync } from 'fs';
import { validate, compareTransactionHash } from './js/validator.js';

const txFile = '/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl';
const lines = readFileSync(txFile, 'utf-8').trim().split('\n');

console.log('=== Transaction Hash Comparison Test ===\n');

const stats = {
    total: 0,
    fullMatch: 0,           // Request + Response + Cert all match
    requestOnlyMatch: 0,    // Request matches but response doesn't
    noResponseInEvidence: 0, // Response not reconstructed (missing from packets)
    reconstructFailed: 0,
    byProtocol: {}
};

for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;

    // Skip WebSocket messages for now
    if (wrapper.type === 'web_socket_message') continue;
    if (!tx.protocol) continue;

    stats.total++;
    const protocol = tx.protocol;
    if (!stats.byProtocol[protocol]) {
        stats.byProtocol[protocol] = {
            total: 0,
            fullMatch: 0,
            requestOnlyMatch: 0,
            noResponse: 0,
            failed: 0
        };
    }
    stats.byProtocol[protocol].total++;

    // First validate to ensure we can decrypt
    const validationResult = await validate(wrapper, { verbose: false });

    if (validationResult.level !== 'full') {
        // Can't do hash comparison if we can't fully validate
        stats.reconstructFailed++;
        stats.byProtocol[protocol].failed++;
        continue;
    }

    // Now try hash comparison
    const result = await compareTransactionHash(tx, { verbose: false });

    if (result.error) {
        stats.reconstructFailed++;
        stats.byProtocol[protocol].failed++;
        continue;
    }

    // Check what matched
    if (result.fullMatch) {
        stats.fullMatch++;
        stats.byProtocol[protocol].fullMatch++;
    } else if (result.requestMatch && !result.responseMatch) {
        // Request matched but response didn't
        // Check if it's because response is null in reconstructed
        if (result.reconstructed?.response === null && tx.response !== null) {
            stats.noResponseInEvidence++;
            stats.byProtocol[protocol].noResponse++;
        } else {
            stats.requestOnlyMatch++;
            stats.byProtocol[protocol].requestOnlyMatch++;
        }
    } else {
        // Neither full match nor request-only match
        stats.requestOnlyMatch++;
        stats.byProtocol[protocol].requestOnlyMatch++;
    }
}

console.log('=== Results ===\n');
console.log(`Total transactions: ${stats.total}`);
console.log(`Full hash match (request+response+cert): ${stats.fullMatch} (${(stats.fullMatch/stats.total*100).toFixed(1)}%)`);
console.log(`Request matches but response missing from evidence: ${stats.noResponseInEvidence}`);
console.log(`Partial/mismatched: ${stats.requestOnlyMatch}`);
console.log(`Reconstruction failed: ${stats.reconstructFailed}`);

console.log('\nBy Protocol:');
for (const [protocol, s] of Object.entries(stats.byProtocol)) {
    const fullPct = (s.fullMatch/s.total*100).toFixed(1);
    console.log(`  ${protocol}:`);
    console.log(`    Total: ${s.total}`);
    console.log(`    Full match: ${s.fullMatch} (${fullPct}%) - COURT READY`);
    console.log(`    Response missing: ${s.noResponse} - request validated, response not in evidence`);
    console.log(`    Other mismatch: ${s.requestOnlyMatch}`);
    console.log(`    Failed: ${s.failed}`);
}

console.log('\n=== Summary ===');
console.log(`Court-ready transactions (full hash match): ${stats.fullMatch}/${stats.total} (${(stats.fullMatch/stats.total*100).toFixed(1)}%)`);
console.log(`\nNote: "Response missing" means the response HEADERS frame is not in the captured packets.`);
console.log(`This is a Keel capture issue - response packets need to be included in forensic evidence.`);
