#!/usr/bin/env node
/**
 * Validate a single transaction from JSONL file
 * Usage: node validate-one.mjs [file] [index|id]
 */

import { readFileSync } from 'fs';
import { webcrypto } from 'crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { validate } from './js/validator.js';

const inputFile = process.argv[2] || '/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl';
const selector = process.argv[3] || '0';

async function main() {
    const lines = readFileSync(inputFile, 'utf-8').trim().split('\n');
    console.log(`Loaded ${lines.length} transactions from ${inputFile}\n`);

    let txWrapper;

    // Find transaction by index or ID
    if (/^\d+$/.test(selector)) {
        const index = parseInt(selector, 10);
        if (index >= lines.length) {
            console.error(`Index ${index} out of range (0-${lines.length - 1})`);
            process.exit(1);
        }
        txWrapper = JSON.parse(lines[index]);
        console.log(`Selected transaction at index ${index}`);
    } else {
        // Search by ID
        for (const line of lines) {
            const wrapper = JSON.parse(line);
            const tx = wrapper.data || wrapper;
            if (tx.id === selector) {
                txWrapper = wrapper;
                break;
            }
        }
        if (!txWrapper) {
            console.error(`Transaction with ID "${selector}" not found`);
            process.exit(1);
        }
        console.log(`Found transaction with ID ${selector}`);
    }

    const tx = txWrapper.data || txWrapper;
    const protocol = tx.protocol || (txWrapper.type === 'web_socket_message' ? 'WebSocket' : 'Unknown');

    console.log(`Protocol: ${protocol}`);
    console.log(`Type: ${txWrapper.type}`);
    if (tx.request?.url) console.log(`URL: ${tx.request.url}`);
    if (tx.request?.method) console.log(`Method: ${tx.request.method}`);
    console.log('');

    // Validate with verbose output
    const result = await validate(txWrapper, { verbose: true });

    console.log('\n=== Validation Result ===');
    console.log(`Valid: ${result.valid}`);
    console.log(`Level: ${result.level}`);
    if (result.error) console.log(`Error: ${result.error}`);

    if (result.details.parsedRequest) {
        console.log('\nParsed Request:');
        console.log(`  Method: ${result.details.parsedRequest.method}`);
        console.log(`  Path: ${result.details.parsedRequest.path}`);
        if (result.details.parsedRequest.authority) {
            console.log(`  Authority: ${result.details.parsedRequest.authority}`);
        }
    }

    if (result.details.parsedResponse) {
        console.log('\nParsed Response:');
        console.log(`  Status: ${result.details.parsedResponse.status}`);
    }

    if (result.details.mismatch) {
        console.log('\nMismatch:');
        console.log('  Claimed:', JSON.stringify(result.details.mismatch.claimed));
        console.log('  Parsed:', JSON.stringify(result.details.mismatch.parsed));
    }
}

main().catch(console.error);
