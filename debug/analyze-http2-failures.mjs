#!/usr/bin/env node
/**
 * Analyze HTTP/2 transactions that don't reach Full validation
 */
import { readFileSync } from 'fs';
import { validate } from './js/validator.js';

const txFile = '/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl';
const lines = readFileSync(txFile, 'utf-8').trim().split('\n');

const failures = [];

console.log('Scanning HTTP/2 transactions...');

for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;

    if (tx.protocol !== 'HTTP/2') continue;
    if (!tx.forensic_evidence) continue;

    const result = await validate(wrapper, { verbose: false });
    const level = result.level?.toLowerCase();

    if (level !== 'full') {
        failures.push({
            id: tx.id,
            url: tx.request?.url?.substring(0, 80),
            level,
            error: result.error,
            hasRequest: !!result.details?.parsedRequest,
            hasResponse: !!result.details?.parsedResponse,
            streamId: tx.forensic_evidence?.h2_stream_id,
            packetCount: tx.forensic_evidence?.raw_packets?.packets?.length || 0,
            appPackets: tx.forensic_evidence?.raw_packets?.packets?.filter(p => p.packet_type === 'application').length || 0,
            hasHpack: !!tx.forensic_evidence?.hpack_request_table || !!tx.forensic_evidence?.hpack_dynamic_table
        });
    }
}

console.log(`\nFound ${failures.length} HTTP/2 transactions not at Full level\n`);

// Group by level
const byLevel = {};
for (const f of failures) {
    const key = f.level || 'unknown';
    if (!byLevel[key]) byLevel[key] = [];
    byLevel[key].push(f);
}

for (const [level, items] of Object.entries(byLevel)) {
    console.log(`\n=== Level: ${level} (${items.length} transactions) ===`);

    // Subgroup by characteristics
    const withRequest = items.filter(f => f.hasRequest);
    const withResponse = items.filter(f => f.hasResponse);
    const withHpack = items.filter(f => f.hasHpack);

    console.log(`  Has parsed request: ${withRequest.length}`);
    console.log(`  Has parsed response: ${withResponse.length}`);
    console.log(`  Has HPACK table: ${withHpack.length}`);

    // Show first few
    console.log(`\n  First 5 examples:`);
    for (const f of items.slice(0, 5)) {
        console.log(`    ${f.id}: stream=${f.streamId}, packets=${f.packetCount} (app=${f.appPackets})`);
        console.log(`      URL: ${f.url}`);
        console.log(`      hasReq=${f.hasRequest}, hasResp=${f.hasResponse}, hpack=${f.hasHpack}`);
        if (f.error) console.log(`      Error: ${f.error}`);
    }
}

// Check for patterns
console.log('\n=== Pattern Analysis ===');

// Low packet counts
const lowPackets = failures.filter(f => f.appPackets < 3);
console.log(`Low app packet count (<3): ${lowPackets.length}`);

// Missing HPACK
const noHpack = failures.filter(f => !f.hasHpack);
console.log(`Missing HPACK table: ${noHpack.length}`);

// Has request but not response
const reqOnly = failures.filter(f => f.hasRequest && !f.hasResponse);
console.log(`Has request but no response: ${reqOnly.length}`);

// Has response but not request
const respOnly = failures.filter(f => !f.hasRequest && f.hasResponse);
console.log(`Has response but no request: ${respOnly.length}`);

// Neither
const neither = failures.filter(f => !f.hasRequest && !f.hasResponse);
console.log(`Has neither request nor response: ${neither.length}`);
