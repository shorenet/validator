#!/usr/bin/env node
import { webcrypto } from 'crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { TlsDecryptor } from './js/crypto/tls.js';
import fs from 'fs';

const line = fs.readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').split('\n')[0];
const tx = JSON.parse(line).data;

function parseKeylog(keylogStr) {
    const keys = {};
    const lines = keylogStr.split('\n');
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const parts = trimmed.split(/\s+/);
        if (parts.length < 3) continue;
        const [label, clientRandom, secret] = parts;
        keys[label.toLowerCase()] = secret;
    }
    return {
        version: keylogStr.includes('CLIENT_TRAFFIC_SECRET_0') ? 'TLS13' : 'TLS12',
        keys
    };
}

const keylog = parseKeylog(tx.forensic_evidence.keylog);
const decryptor = new TlsDecryptor();
await decryptor.initialize(keylog);

const clientKeyBytes = await crypto.subtle.exportKey('raw', decryptor.clientKey);
const clientKey = Buffer.from(clientKeyBytes).toString('hex');
const clientIv = Buffer.from(decryptor.clientIv).toString('hex');

console.log('JavaScript derived:');
console.log('  Client key:', clientKey);
console.log('  Client IV:', clientIv);
console.log('');
console.log('Python derived:');
console.log('  Client key: ece565ff1df5f2ee00d5fffea4dca7b1f865101436058d2d985acc3edb18db0c');
console.log('  Client IV: 7ed4967d2f40e3cef0133df1');
console.log('');
console.log('Match?', clientKey === 'ece565ff1df5f2ee00d5fffea4dca7b1f865101436058d2d985acc3edb18db0c');
