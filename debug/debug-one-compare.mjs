#!/usr/bin/env node
/**
 * Debug: Run hash comparison on one transaction with verbose output
 */
import { readFileSync } from 'fs';
import { compareTransactionHash, validate } from './js/validator.js';

const txFile = '/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl';
const lines = readFileSync(txFile, 'utf-8').trim().split('\n');

// Find first HTTP/2 transaction where response fails
for (const line of lines) {
    const wrapper = JSON.parse(line);
    const tx = wrapper.data || wrapper;

    if (tx.protocol !== 'HTTP/2') continue;
    if (!tx.forensic_evidence) continue;
    if (tx.response === null) continue;

    // Run hash comparison first (without verbose)
    const result = await compareTransactionHash(tx, { verbose: false });

    // Skip full matches - we want to find a failure
    if (result.fullMatch) continue;
    // Skip errors
    if (result.error) continue;
    // Find ones where response is null in reconstructed but not in original
    if (result.reconstructed?.response !== null) continue;

    console.log('=== Transaction with Missing Response ===');
    console.log('ID:', tx.id);
    console.log('URL:', tx.request?.url);
    console.log('Stream ID:', tx.forensic_evidence.h2_stream_id);
    console.log('');

    // Run validation with verbose
    const validationResult = await validate(wrapper, { verbose: true });
    console.log('\n=== Validation Result ===');
    console.log('Level:', validationResult.level);
    if (validationResult.error) {
        console.log('Error:', validationResult.error);
    }
    console.log('');

    // Run hash comparison with verbose
    console.log('\n=== Hash Comparison (verbose) ===');
    const resultVerbose = await compareTransactionHash(tx, { verbose: true });
    console.log('Full match:', resultVerbose.fullMatch);
    console.log('Request match:', resultVerbose.requestMatch);
    console.log('Response match:', resultVerbose.responseMatch);
    console.log('Cert match:', resultVerbose.certMatch);

    if (resultVerbose.error) {
        console.log('Error:', resultVerbose.error);
    }

    console.log('\nReconstructed response:', resultVerbose.reconstructed?.response ? 'present' : 'NULL');
    console.log('Original response:', tx.response ? 'present' : 'NULL');

    break;
}
