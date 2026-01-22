#!/usr/bin/env node
/**
 * Extract broken HTTP/2 transactions to a smaller file for faster debugging
 * A transaction is "broken" if it doesn't reach Full validation level
 */
import { readFileSync, writeFileSync } from 'fs';
import { validate } from './js/validator.js';

const txFile = '/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl';
const outputFile = '/Users/ant/Projects/harbour/test-fixtures/captures/latest/broken_http2.jsonl';

const lines = readFileSync(txFile, 'utf-8').trim().split('\n');

const broken = [];
const stats = {
    total: 0,
    http2: 0,
    full: 0,
    partial: 0,
    failed: 0,
    reasons: {}
};

console.log('Scanning transactions...');

for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;

    stats.total++;

    if (tx.protocol !== 'HTTP/2') continue;
    stats.http2++;

    try {
        const result = await validate({ type: 'transaction', data: tx }, { verbose: false });

        if (result.level === 'Full') {
            stats.full++;
        } else {
            // Not full - add to broken list
            stats.partial++;
            const reason = result.error || result.level || 'unknown';
            stats.reasons[reason] = (stats.reasons[reason] || 0) + 1;

            broken.push({
                line: line,
                tx_id: tx.id,
                level: result.level,
                error: result.error,
                url: tx.request?.url?.substring(0, 80)
            });
        }
    } catch (e) {
        stats.failed++;
        stats.reasons[e.message] = (stats.reasons[e.message] || 0) + 1;
        broken.push({
            line: line,
            tx_id: tx.id,
            level: 'Error',
            error: e.message,
            url: tx.request?.url?.substring(0, 80)
        });
    }
}

console.log('\n=== Results ===');
console.log(`Total transactions: ${stats.total}`);
console.log(`HTTP/2 transactions: ${stats.http2}`);
console.log(`Full validation: ${stats.full} (${(stats.full/stats.http2*100).toFixed(1)}%)`);
console.log(`Not Full: ${stats.partial}`);
console.log(`Errors: ${stats.failed}`);
console.log(`\nBroken transactions: ${broken.length}`);

// Write broken transactions
const brokenLines = broken.map(b => b.line).join('\n');
writeFileSync(outputFile, brokenLines + '\n');
console.log(`\nWritten to: ${outputFile}`);

// Show breakdown by reason
console.log('\n=== Breakdown by Reason ===');
const sortedReasons = Object.entries(stats.reasons).sort((a, b) => b[1] - a[1]);
for (const [reason, count] of sortedReasons) {
    console.log(`  ${count}x ${reason}`);
}

// Show first few broken transactions
console.log('\n=== First 10 Broken Transactions ===');
for (const b of broken.slice(0, 10)) {
    console.log(`${b.tx_id}: ${b.level} - ${b.error || 'no error'}`);
    console.log(`  URL: ${b.url}`);
}
