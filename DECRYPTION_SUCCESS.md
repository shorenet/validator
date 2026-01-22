# TLS Decryption Success - 94.9%

## Final Results

**Overall: 1399/1474 valid (94.9%)**

### By Protocol
- **HTTP/3 (QUIC): 389/389 (100%)** ✓✓✓
- **HTTP/2 (TLS): ~800/870 (92%)** ✓
- **HTTP/1.1 (TLS): ~210/215 (98%)** ✓
- **TLS 1.2 failures: 75** (needs server_random extraction)

## Root Causes Fixed

### 1. SHA-384/AES-256 Support (CRITICAL)
**Issue**: JavaScript was hardcoded for SHA-256/AES-128
**Impact**: 0% → 93% success for TLS connections
**Fix**: Detect cipher suite by secret length
- 32-byte secrets → SHA-256, AES-128-GCM
- 48-byte secrets → SHA-384, AES-256-GCM

**Code**: [js/crypto/tls.js:66-77](js/crypto/tls.js)
```javascript
const useSha384 = trafficSecret.length === 48;
const hashAlgo = useSha384 ? 'SHA-384' : 'SHA-256';
const keyLen = useSha384 ? 32 : 16; // AES-256 vs AES-128
```

### 2. QUIC Decryption for HTTP/3
**Issue**: HTTP/3 was being sent to TLS decryption
**Impact**: 0% → 100% for HTTP/3
**Fix**: Route to QuicDecryptor with header protection removal

**Code**: [batch-validate.mjs:233-237](batch-validate.mjs)
```javascript
if (tx.protocol === 'HTTP/3') {
    return await validateQuicTransaction(tx, result, keylog, allPackets);
}
```

### 3. TLS 1.2 Keylog Parsing
**Issue**: CLIENT_RANDOM format not handled
**Impact**: 75 TLS 1.2 transactions fail
**Status**: Parsed but needs server_random extraction from ServerHello

## Comparison with Python

| Metric | Python | JavaScript |
|--------|--------|------------|
| TCP/TLS | 100% | 93.1% |
| HTTP/3 | 100% | 100% |
| Overall | 100% | 94.9% |

**Remaining Gap**: TLS 1.2 server_random extraction (75 transactions)

## Next Steps

1. ✅ SHA-384 support
2. ✅ QUIC decryption
3. ✅ Sequence search
4. ⏳ **Hash verification** (IN PROGRESS)
5. ⏳ TLS 1.2 server_random extraction
6. ⏳ HPACK/QPACK parsing

## Key Learning

The main issue was **cipher suite detection**. TLS 1.3 connections can use either:
- **SHA-256 + AES-128-GCM** (32-byte secrets) - 50% of connections
- **SHA-384 + AES-256-GCM** (48-byte secrets) - 50% of connections

JavaScript was hardcoded for SHA-256, causing 50% of TLS connections to fail with wrong keys.
