# Harbour Forensic Evidence Validator

Browser-based validator for HTTP and WebSocket transaction forensic evidence.

## Features

- **100% Browser-Based**: Runs entirely in your browser using WebCrypto
- **No Server Required**: All validation happens client-side
- **Full TLS Verification**: Validates CertificateVerify signatures, certificate chains
- **Protocol Support**: HTTP/1.1, HTTP/2, HTTP/3, WebSocket

## Usage

### Online

Visit [validator.shorenet.io](https://validator.shorenet.io) to use the hosted version.

### Local

```bash
# Serve locally (no install needed)
npx serve .
# Open http://localhost:3000
```

Or with Python:
```bash
python3 -m http.server 8000
# Open http://localhost:8000
```

### Node.js (for batch validation)

```bash
npm install
node -e "import('./src/index.js').then(m => console.log('Validator loaded'))"
```

## How It Works

1. **Drop or paste** a JSONL file containing transactions with forensic evidence
2. The validator **reconstructs** each transaction from raw packet data
3. **Cryptographic verification** ensures the evidence wasn't tampered with:
   - TLS handshake signatures (CertificateVerify, ServerKeyExchange)
   - Certificate chain validation against Mozilla root store
   - Transaction hash comparison

## Validation Levels

| Level | Description |
|-------|-------------|
| **Full** | Complete reconstruction matches original transaction |
| **Parse** | Successfully parsed but some fields differ |
| **Decrypt** | TLS decryption succeeded but parsing failed |
| **Failed** | Could not validate the evidence |

## API

```javascript
import { validate } from './src/index.js';

// Validate a transaction
const result = await validate(transactionWrapper, {
  verbose: false,
  skipCtLookup: true  // Skip Certificate Transparency lookup
});

console.log(result.valid);  // true/false
console.log(result.level);  // 'full', 'parse', 'decrypt', or 'none'
```

## Security

This validator runs entirely in your browser. **No data is sent to any server.**

All cryptographic operations use:
- **WebCrypto API** for signature verification
- **@peculiar/x509** for certificate parsing
- **@noble/ed25519** for Ed25519 signatures

## Browser Compatibility

Works in all modern browsers with WebCrypto support:
- Chrome 60+
- Firefox 75+
- Safari 14+
- Edge 79+

## License

MIT
