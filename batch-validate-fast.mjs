#!/usr/bin/env node
/**
 * Fast batch validation - summary only, no verbose logging
 */
import { readFileSync } from 'fs';
import { validate } from './js/validator.js';

const txFile = process.argv[2] || '/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl';
const lines = readFileSync(txFile, 'utf-8').trim().split('\n');

const stats = {
    total: 0,
    withEvidence: 0,
    valid: 0,
    levels: { Full: 0, Parse: 0, Decrypt: 0, Connection: 0 },
    failed: 0,
    noEvidence: 0,
    byProtocol: {}
};

const startTime = Date.now();
let processed = 0;

for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;
    stats.total++;

    if (!tx.forensic_evidence) {
        stats.noEvidence++;
        continue;
    }
    stats.withEvidence++;

    const protocol = tx.protocol || 'Unknown';
    if (!stats.byProtocol[protocol]) {
        stats.byProtocol[protocol] = { total: 0, full: 0, parse: 0, decrypt: 0, failed: 0 };
    }
    stats.byProtocol[protocol].total++;

    try {
        // Run validation WITHOUT verbose
        const result = await validate(wrapper, { verbose: false });

        const level = result.level?.toLowerCase();
        if (level === 'full') {
            stats.levels.Full++;
            stats.byProtocol[protocol].full++;
        } else if (level === 'parse') {
            stats.levels.Parse++;
            stats.byProtocol[protocol].parse++;
        } else if (level === 'decrypt') {
            stats.levels.Decrypt++;
            stats.byProtocol[protocol].decrypt++;
        } else if (level === 'connection') {
            stats.levels.Connection++;
        }
        stats.valid++;
    } catch (e) {
        stats.failed++;
        stats.byProtocol[protocol].failed++;
    }

    processed++;
    if (processed % 200 === 0) {
        process.stdout.write(`\rProcessed: ${processed}/${stats.total}...`);
    }
}

const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
console.log(`\r${'='.repeat(60)}\n`);

console.log('Results:');
console.log(`  Total transactions: ${stats.total}`);
console.log(`  With forensic evidence: ${stats.withEvidence}`);
console.log(`  Valid: ${stats.valid} (${(stats.valid/stats.withEvidence*100).toFixed(1)}%)`);
console.log(`    - Full (decrypt+parse+match): ${stats.levels.Full}`);
console.log(`    - Parse (decrypt+parse, no comparison): ${stats.levels.Parse}`);
console.log(`    - Decrypt only: ${stats.levels.Decrypt}`);
console.log(`    - Connection setup: ${stats.levels.Connection}`);
console.log(`  Failed: ${stats.failed}`);
console.log(`  No evidence: ${stats.noEvidence}`);
console.log(`  Time: ${elapsed}s`);

// Protocol breakdown
console.log('\nBy Protocol:');
for (const [proto, s] of Object.entries(stats.byProtocol).sort((a,b) => b[1].total - a[1].total)) {
    const fullPct = s.total > 0 ? (s.full/s.total*100).toFixed(1) : 0;
    console.log(`  ${proto}: ${s.full}/${s.total} Full (${fullPct}%), ${s.parse} Parse, ${s.decrypt} Decrypt, ${s.failed} Failed`);
}
