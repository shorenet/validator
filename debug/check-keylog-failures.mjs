#!/usr/bin/env node
import fs from 'fs';

const lines = fs.readFileSync('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'utf-8').split('\n').filter(l => l.trim());

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

let failures = 0;
for (let i = 0; i < lines.length; i++) {
    const tx = JSON.parse(lines[i]).data;
    if (!tx.forensic_evidence || !tx.forensic_evidence.keylog) continue;

    const keylog = parseKeylog(tx.forensic_evidence.keylog);

    // Check if we have required keys
    const hasTls13 = keylog.keys.client_traffic_secret_0 && keylog.keys.server_traffic_secret_0;
    const hasTls12 = keylog.keys.master_secret;

    if (!hasTls13 && !hasTls12) {
        failures++;
        if (failures <= 5) {
            console.log(`\nTransaction ${tx.id} [${tx.protocol}]:`);
            console.log('Keylog keys:', Object.keys(keylog.keys));
            console.log('First 200 chars of keylog:', tx.forensic_evidence.keylog.substring(0, 200));
        }
    }
}

console.log(`\nTotal keylog parse failures: ${failures}`);
