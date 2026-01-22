#!/usr/bin/env node
import { readFileSync } from 'fs';
import { webcrypto } from 'crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { validate } from './js/validator.js';

const lines = readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').trim().split('\n');

const failures = [];
let count = 0;

for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;
    if (tx.protocol !== 'HTTP/2') continue;
    count++;

    const result = await validate(wrapper, { verbose: false });
    if (!result.valid) {
        failures.push({ id: tx.id, error: result.error, url: tx.request?.url?.substring(0, 60) });
    }
}

console.log('Total HTTP/2:', count);
console.log('Failures:', failures.length);
console.log('');
console.log('Sample failures:');
for (const f of failures.slice(0, 10)) {
    console.log('  ' + f.id + ': ' + f.error);
    console.log('    URL: ' + f.url);
}
