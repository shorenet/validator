#!/usr/bin/env node
/**
 * Batch validator for Harbour transactions
 * Uses modular validator for all protocols
 */

import { createReadStream } from 'fs';
import { createInterface } from 'readline';
import { webcrypto } from 'crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { validate } from './js/validator.js';

const inputFile = process.argv[2] || '/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl';

// Suppress verbose logging during batch
const originalLog = console.log;
const originalWarn = console.warn;
let suppressLogs = true;
console.log = (...args) => { if (!suppressLogs) originalLog(...args); };
console.warn = (...args) => { if (!suppressLogs) originalWarn(...args); };

async function main() {
    suppressLogs = false;
    console.log(`Validating transactions from: ${inputFile}\n`);
    suppressLogs = true;

    const rl = createInterface({
        input: createReadStream(inputFile),
        crlfDelay: Infinity
    });

    const results = {
        total: 0,
        withEvidence: 0,
        valid: 0,
        failed: 0,
        noEvidence: 0,
        levels: { none: 0, decrypt: 0, parse: 0, full: 0 },
        byProtocol: {},
        failures: [],
        mismatches: 0
    };

    const startTime = Date.now();

    for await (const line of rl) {
        if (!line.trim()) continue;

        results.total++;
        const txWrapper = JSON.parse(line);
        const tx = txWrapper.data || txWrapper;
        const protocol = tx.protocol || (txWrapper.type === 'web_socket_message' ? 'WebSocket' : 'Unknown');

        if (!results.byProtocol[protocol]) {
            results.byProtocol[protocol] = { valid: 0, failed: 0, levels: { none: 0, decrypt: 0, parse: 0, full: 0 } };
        }

        const evidence = tx.forensic_evidence;
        if (!evidence) {
            results.noEvidence++;
            results.byProtocol[protocol].failed++;
            continue;
        }

        results.withEvidence++;

        try {
            const result = await validate(txWrapper, { verbose: false });

            if (result.valid) {
                results.valid++;
                results.byProtocol[protocol].valid++;
            } else {
                results.failed++;
                results.byProtocol[protocol].failed++;
                results.failures.push({
                    id: tx.id,
                    protocol,
                    error: result.error
                });
            }

            results.levels[result.level]++;
            results.byProtocol[protocol].levels[result.level]++;

            if (result.details?.mismatch) {
                results.mismatches++;
            }
        } catch (e) {
            results.failed++;
            results.byProtocol[protocol].failed++;
            results.failures.push({
                id: tx.id,
                protocol,
                error: e.message
            });
        }

        // Progress update
        if (results.total % 100 === 0) {
            suppressLogs = false;
            console.log(`Processed ${results.total}...`);
            suppressLogs = true;
        }
    }

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);

    suppressLogs = false;

    console.log('\n============================================================\n');
    console.log('Results:');
    console.log(`  Total transactions: ${results.total}`);
    console.log(`  With forensic evidence: ${results.withEvidence}`);
    console.log(`  Valid: ${results.valid} (${(results.valid / results.withEvidence * 100).toFixed(1)}%)`);
    console.log(`    - Full (decrypt+parse+match): ${results.levels.full}`);
    console.log(`    - Parse (decrypt+parse): ${results.levels.parse}`);
    console.log(`    - Decrypt only: ${results.levels.decrypt}`);
    console.log(`    - None: ${results.levels.none}`);
    console.log(`  Field mismatches: ${results.mismatches}`);
    console.log(`  Failed: ${results.failed}`);
    console.log(`  No evidence: ${results.noEvidence}`);
    console.log(`  Time: ${elapsed}s`);

    console.log('\nBy protocol:');
    for (const [proto, stats] of Object.entries(results.byProtocol).sort()) {
        const total = stats.valid + stats.failed;
        console.log(`  ${proto}: ${stats.valid}/${total} valid (${(stats.valid / total * 100).toFixed(1)}%)`);
        console.log(`    Levels: full=${stats.levels.full}, parse=${stats.levels.parse}, decrypt=${stats.levels.decrypt}, none=${stats.levels.none}`);
    }

    if (results.failures.length > 0 && results.failures.length <= 20) {
        console.log('\nFailures:');
        for (const f of results.failures) {
            console.log(`  [${f.protocol}] ${f.id}: ${f.error}`);
        }
    } else if (results.failures.length > 20) {
        console.log(`\nFirst 20 failures (of ${results.failures.length}):`);
        for (const f of results.failures.slice(0, 20)) {
            console.log(`  [${f.protocol}] ${f.id}: ${f.error}`);
        }
    }
}

main().catch(console.error);
