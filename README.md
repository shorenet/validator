# Shorenet Forensic Evidence Validator

A browser-based tool for independently verifying network capture evidence exported from [Trawler](https://shorenet.co.uk).

**Live validator:** https://shorenet.github.io/validator

## What it does

This validator allows anyone to verify forensic evidence from Shorenet captures:

1. **Hash Chain Verification** - Verifies SHA-256 hash chain integrity of raw packets
2. **TLS Decryption** - Decrypts TLS 1.2/1.3 records using provided keylog data
3. **Protocol Parsing** - Parses HTTP/1.1, HTTP/2 (HPACK), HTTP/3 (QPACK), and WebSocket
4. **Certificate Display** - Shows the TLS certificate chain from the handshake
5. **Content Verification** - Verifies body content hashes match

## Privacy

**All validation runs entirely in your browser.** No data is sent to any server. You can verify this by:
- Inspecting the source code
- Checking network requests in browser DevTools
- Running offline after initial page load

## Usage

1. Export forensic evidence JSON from Trawler
2. Go to https://shorenet.github.io/validator
3. Either:
   - Drop the JSON file onto the drop zone
   - Paste the JSON directly into the text area
4. View validation results

## Deploying to GitHub Pages

### Initial Setup

1. Create the GitHub repository:
   ```bash
   cd /Users/ant/Projects/validator
   git init
   git add .
   git commit -m "Initial commit: forensic evidence validator"
   ```

2. Create repo on GitHub (https://github.com/new):
   - Repository name: `validator`
   - Owner: `shorenet` (organization)
   - Public repository

3. Push to GitHub:
   ```bash
   git remote add origin git@github.com:shorenet/validator.git
   git branch -M main
   git push -u origin main
   ```

4. Enable GitHub Pages:
   - Go to repository Settings → Pages
   - Source: "Deploy from a branch"
   - Branch: `main` / `/ (root)`
   - Click Save

5. Wait 1-2 minutes, then visit: https://shorenet.github.io/validator

### Updating

After making changes:
```bash
git add .
git commit -m "Description of changes"
git push
```

GitHub Pages will automatically redeploy within a minute.

## Local Development

ES modules require a web server. You can't just open `index.html` directly.

### Option 1: Python (built-in)
```bash
cd /Users/ant/Projects/validator
python3 -m http.server 8000
# Open http://localhost:8000
```

### Option 2: Node.js
```bash
npx serve .
# Open http://localhost:3000
```

### Option 3: VS Code Live Server
Install the "Live Server" extension, then right-click `index.html` → "Open with Live Server"

## Project Structure

```
validator/
├── index.html              # Main HTML
├── css/
│   └── style.css           # Styles
└── js/
    ├── main.js             # Orchestration
    ├── crypto/
    │   ├── hash.js         # SHA-256, hash chain verification
    │   ├── tls.js          # TLS 1.2/1.3 decryption
    │   └── certificate.js  # X.509 parsing
    └── protocol/
        ├── http1.js        # HTTP/1.x parser
        ├── http2.js        # HTTP/2 + HPACK
        ├── http3.js        # HTTP/3 + QPACK
        └── websocket.js    # WebSocket frames
```

## Evidence Format

The validator accepts JSON in these formats:

### Transaction (HTTP)
```json
{
  "id": "01HXYZ...",
  "protocol": "HTTP/2",
  "request": {
    "method": "GET",
    "url": "https://example.com/api",
    "headers": {...}
  },
  "response": {
    "status": 200,
    "headers": {...}
  },
  "forensic_evidence": {
    "keylog": "CLIENT_RANDOM ...",
    "raw_packets": {...},
    "certificate_info": {...}
  }
}
```

### WebSocket Message
```json
{
  "id": "01HXYZ...",
  "message_type": "Text",
  "direction": "ClientToServer",
  "payload": "base64...",
  "url": "wss://example.com/ws",
  "forensic_evidence": {...}
}
```

### CapturedEvent Wrapper
```json
{
  "type": "transaction",
  "data": { /* Transaction */ }
}
```

## License

MIT License - See LICENSE file

## Links

- [Shorenet](https://shorenet.co.uk) - Network forensics platform
- [Source Code](https://github.com/shorenet/validator) - This repository
