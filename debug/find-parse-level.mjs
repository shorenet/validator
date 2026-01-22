#!/usr/bin/env node
import { readFileSync } from 'fs';
import { webcrypto } from 'crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { validate } from './js/validator.js';

const lines = readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').trim().split('\n');

let found = 0;
for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;
    if (tx.protocol !== 'HTTP/2') continue;

    const result = await validate(wrapper, { verbose: false });
    if (result.level === 'parse') {
        console.log('ID:', tx.id);
        console.log('URL:', tx.request?.url);
        console.log('Result:', result);
        found++;
        if (found >= 3) break;
    }
}
