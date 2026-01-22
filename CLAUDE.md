# CLAUDE.md - Validator

This file provides guidance to Claude Code when working with the validator codebase.

## Project Overview

**Validator** is a browser-based forensic evidence validator for [Harbour/Trawler](https://github.com/shorenet/harbour). It independently verifies network capture evidence by:

1. Decrypting TLS 1.2/1.3 traffic using keylog data
2. Parsing HTTP/1.1, HTTP/2 (HPACK), HTTP/3 (QPACK), and WebSocket protocols
3. Verifying hash chain integrity and content hashes
4. Comparing reconstructed data against original captures

**Live validator:** https://shorenet.github.io/validator

## Project Structure

```
validator/
├── index.html              # Web UI (drop zone, validation display)
├── batch-validate.mjs      # Full verbose batch validation CLI
├── batch-validate-fast.mjs # Fast summary batch validation CLI
├── validate-one.mjs        # Single transaction validation CLI
├── css/
│   └── style.css           # Web UI styles
├── js/
│   ├── main.js             # Web UI orchestration
│   ├── validator.js        # Core validation logic (all protocols)
│   ├── crypto/
│   │   ├── hash.js         # SHA-256, hash chain verification, base64
│   │   ├── tls.js          # TLS 1.2/1.3 decryption (AEAD)
│   │   ├── quic.js         # QUIC Initial packet decryption
│   │   └── certificate.js  # X.509 certificate parsing
│   └── protocol/
│       ├── http1.js        # HTTP/1.x parser
│       ├── http2.js        # HTTP/2 frame + HPACK decoder
│       ├── http3.js        # HTTP/3 frame + QPACK decoder
│       ├── hpack.js        # HPACK header compression
│       ├── tcp.js          # TCP segment extraction + reassembly
│       └── websocket.js    # WebSocket frame parser
└── debug/                  # Debug scripts (not for production)
```

## Running Validation

### CLI Batch Validation

```bash
# Fast summary (for quick checks)
node batch-validate-fast.mjs [path/to/transactions.jsonl]

# Full verbose (for debugging)
node batch-validate.mjs [path/to/transactions.jsonl]

# Single transaction
node validate-one.mjs <transaction-id>
```

Default transaction file: `/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl`

### Web Interface

```bash
# Start local server
python3 -m http.server 8000
# Open http://localhost:8000
```

## Validation Levels

1. **Full** - Successfully decrypted, parsed, AND reconstructed data matches original
2. **Parse** - Successfully decrypted and parsed, but couldn't compare (missing original data)
3. **Decrypt** - Successfully decrypted TLS, but couldn't parse protocol
4. **Connection** - Could only verify connection setup (handshake)

## Debug Scripts

The `debug/` directory contains one-off debugging scripts. These are NOT production code.

**Key debug scripts:**
- `debug-missing-request.mjs` - Debug transaction where request HEADERS not found
- `analyze-http2-failures.mjs` - Analyze HTTP/2 transactions not at Full level
- `extract-broken.mjs` - Extract broken transactions to smaller file
- `debug-tcp-gaps.mjs` - Analyze TCP sequence gaps/overlaps

**Adding new debug scripts:**
1. Create script in `debug/` folder
2. Use shebang: `#!/usr/bin/env node`
3. Import from `../js/` for validator modules

## Key Implementation Details

### TLS Decryption (`js/crypto/tls.js`)

- Supports TLS 1.2 (GCM cipher suites) and TLS 1.3
- Uses WebCrypto API for AES-GCM decryption
- TLS 1.3: Filters post-handshake messages (NewSessionTicket, KeyUpdate)
- Key derivation uses HKDF with appropriate labels

### HTTP/2 Validation (`js/validator.js:validateHttp2`)

- Uses HPACK snapshots from forensic evidence to reconstruct headers
- Filters frames by `h2_stream_id` from forensic evidence
- Reconstructs request/response independently using HPACK table state

### TCP Handling (`js/protocol/tcp.js`)

- `extractTcpSegment()` - Extract TCP payload from raw packet
- `reassembleTcpStream()` - Reassemble ordered segments (handles overlaps)
- Current validation uses simple concatenation (segments already ordered by Keel)

## Common Issues

1. **"HPACK snapshot missing"** - Forensic evidence lacks HPACK table state
2. **"Request HEADERS not found"** - Packets don't contain HEADERS frame for stream
3. **"Decrypt failed"** - Keylog mismatch or TLS record corruption
4. **TCP overlaps** - Packets have overlapping sequence numbers (handled by dedup)

## Transaction File Format

Each line is JSON-wrapped:
```json
{"type": "transaction", "data": { /* Transaction object */ }}
```

Access transaction: `JSON.parse(line).data`

## Privacy

All validation runs entirely in the browser. No data is sent to any server.
