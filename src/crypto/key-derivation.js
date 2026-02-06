/**
 * TLS 1.3 and QUIC key derivation using HKDF
 * Implements key derivation as specified in RFC 8446 (TLS 1.3) and RFC 9001 (QUIC-TLS)
 */

/**
 * HKDF-Expand-Label for TLS 1.3 (RFC 8446 Section 7.1)
 *
 * @param {CryptoKey|Uint8Array} secret - The secret key (HMAC key or raw bytes)
 * @param {string} label - Label string (without "tls13 " prefix)
 * @param {Uint8Array} context - Context data (usually empty or hash)
 * @param {number} length - Output length in bytes
 * @param {string} hashAlgo - Hash algorithm ('SHA-256' or 'SHA-384')
 * @returns {Promise<Uint8Array>} Derived key material
 */
export async function hkdfExpandLabel(secret, label, context, length, hashAlgo = 'SHA-256') {
    const labelBytes = new TextEncoder().encode('tls13 ' + label);

    // HkdfLabel structure:
    // uint16 length;
    // opaque label<7..255>;
    // opaque context<0..255>;
    const hkdfLabel = new Uint8Array(2 + 1 + labelBytes.length + 1 + context.length);
    hkdfLabel[0] = (length >> 8) & 0xff;
    hkdfLabel[1] = length & 0xff;
    hkdfLabel[2] = labelBytes.length;
    hkdfLabel.set(labelBytes, 3);
    hkdfLabel[3 + labelBytes.length] = context.length;
    hkdfLabel.set(context, 3 + labelBytes.length + 1);

    // Build info || counter for HKDF-Expand
    const infoWithCounter = new Uint8Array(hkdfLabel.length + 1);
    infoWithCounter.set(hkdfLabel);
    infoWithCounter[hkdfLabel.length] = 0x01;  // Counter for first iteration

    // Convert secret to HMAC key if it's raw bytes
    let hmacKey;
    if (secret instanceof CryptoKey) {
        // Already a CryptoKey - export and reimport with correct hash
        const secretBytes = await crypto.subtle.exportKey('raw', secret);
        hmacKey = await crypto.subtle.importKey(
            'raw',
            secretBytes,
            { name: 'HMAC', hash: hashAlgo },
            false,
            ['sign']
        );
    } else {
        // Raw bytes - import as HMAC key
        hmacKey = await crypto.subtle.importKey(
            'raw',
            secret,
            { name: 'HMAC', hash: hashAlgo },
            false,
            ['sign']
        );
    }

    // HKDF-Expand: HMAC(PRK, info || 0x01)
    const signature = await crypto.subtle.sign('HMAC', hmacKey, infoWithCounter);

    // Return first 'length' bytes
    return new Uint8Array(signature).slice(0, length);
}

/**
 * QUIC-specific HKDF-Expand-Label (RFC 9001)
 * Uses "tls13 quic " prefix instead of "tls13 "
 *
 * @param {Uint8Array} secret - Traffic secret
 * @param {string} label - Label (without "tls13 quic " prefix)
 * @param {Uint8Array} context - Context (usually empty)
 * @param {number} length - Output length
 * @returns {Promise<Uint8Array>} Derived key material
 */
export async function quicHkdfExpandLabel(secret, label, context, length) {
    // QUIC uses "tls13 quic <label>" format
    const fullLabel = new TextEncoder().encode('tls13 quic ' + label);

    // HKDF label structure
    const hkdfLabel = new Uint8Array(2 + 1 + fullLabel.length + 1 + context.length);
    hkdfLabel[0] = (length >> 8) & 0xff;
    hkdfLabel[1] = length & 0xff;
    hkdfLabel[2] = fullLabel.length;
    hkdfLabel.set(fullLabel, 3);
    hkdfLabel[3 + fullLabel.length] = context.length;
    hkdfLabel.set(context, 3 + fullLabel.length + 1);

    // HKDF-Expand using HMAC-SHA256
    const hmacKey = await crypto.subtle.importKey(
        'raw',
        secret,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );

    const hashLen = 32;
    const n = Math.ceil(length / hashLen);
    const okm = new Uint8Array(n * hashLen);
    let t = new Uint8Array(0);

    for (let i = 1; i <= n; i++) {
        const input = new Uint8Array(t.length + hkdfLabel.length + 1);
        input.set(t, 0);
        input.set(hkdfLabel, t.length);
        input[t.length + hkdfLabel.length] = i;

        const sig = await crypto.subtle.sign('HMAC', hmacKey, input);
        t = new Uint8Array(sig);
        okm.set(t, (i - 1) * hashLen);
    }

    return okm.slice(0, length);
}

/**
 * Derive TLS 1.3 traffic keys from a traffic secret
 *
 * @param {Uint8Array} trafficSecret - The traffic secret bytes
 * @returns {Promise<{key: CryptoKey, iv: Uint8Array}>} Derived key and IV
 */
export async function deriveTrafficKeys(trafficSecret) {
    // Detect cipher suite by secret length (SHA384 uses 48-byte secrets)
    const useSha384 = trafficSecret.length === 48;
    const hashAlgo = useSha384 ? 'SHA-384' : 'SHA-256';
    const keyLen = useSha384 ? 32 : 16; // AES-256 vs AES-128

    // Import as HMAC key first to use for HKDF
    const hmacKey = await crypto.subtle.importKey(
        'raw',
        trafficSecret,
        { name: 'HMAC', hash: hashAlgo },
        true,
        ['sign']
    );

    // Derive key
    const keyBytes = await hkdfExpandLabel(hmacKey, 'key', new Uint8Array(0), keyLen, hashAlgo);

    // Derive IV (always 12 bytes)
    const iv = await hkdfExpandLabel(hmacKey, 'iv', new Uint8Array(0), 12, hashAlgo);

    // Import as AES-GCM key
    const key = await crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'AES-GCM' },
        true,  // extractable for debugging
        ['decrypt']
    );

    return { key, iv };
}

/**
 * Derive QUIC encryption keys from a traffic secret
 *
 * @param {Uint8Array} secret - Traffic secret (32 bytes)
 * @returns {Promise<{key: CryptoKey, keyBytes: Uint8Array, iv: Uint8Array, hpKey: CryptoKey, hpKeyBytes: Uint8Array}>}
 */
export async function deriveQuicKeys(secret) {
    const keyBytes = await quicHkdfExpandLabel(secret, 'key', new Uint8Array(0), 16);
    const iv = await quicHkdfExpandLabel(secret, 'iv', new Uint8Array(0), 12);
    const hpKeyBytes = await quicHkdfExpandLabel(secret, 'hp', new Uint8Array(0), 16);

    const key = await crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );

    const hpKey = await crypto.subtle.importKey(
        'raw',
        hpKeyBytes,
        { name: 'AES-CBC' },  // Used for ECB simulation
        true,  // Need to export for ECB simulation
        ['encrypt']
    );

    return { key, keyBytes, iv, hpKey, hpKeyBytes };
}

/**
 * QUIC v1 Initial salt (RFC 9001 Section 5.2)
 */
const QUIC_V1_INITIAL_SALT = new Uint8Array([
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a
]);

/**
 * Derive QUIC Initial keys from Destination Connection ID (DCID)
 * RFC 9001 Section 5.2
 *
 * @param {Uint8Array} dcid - Destination Connection ID from first client Initial packet
 * @returns {Promise<{clientKeys: Object, serverKeys: Object}>}
 */
export async function deriveQuicInitialKeys(dcid) {
    // Initial secret = HKDF-Extract(initial_salt, DCID)
    const initialSecretKey = await crypto.subtle.importKey(
        'raw',
        QUIC_V1_INITIAL_SALT,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const initialSecretSig = await crypto.subtle.sign('HMAC', initialSecretKey, dcid);
    const initialSecret = new Uint8Array(initialSecretSig);

    // Client initial secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
    // Note: Initial secrets use "tls13 " prefix, not "tls13 quic "
    const clientInitialSecret = await hkdfExpandLabel(initialSecret, 'client in', new Uint8Array(0), 32, 'SHA-256');

    // Server initial secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
    const serverInitialSecret = await hkdfExpandLabel(initialSecret, 'server in', new Uint8Array(0), 32, 'SHA-256');

    // Derive keys from Initial secrets using QUIC key derivation
    // Note: For Initial keys, we also use "tls13 " prefix (not "tls13 quic ")
    const clientKeys = await deriveQuicInitialKeysFromSecret(clientInitialSecret);
    const serverKeys = await deriveQuicInitialKeysFromSecret(serverInitialSecret);

    return { clientKeys, serverKeys };
}

/**
 * Derive QUIC Initial encryption keys from an Initial traffic secret
 * Uses "tls13 " prefix (not "tls13 quic ") for Initial keys
 */
async function deriveQuicInitialKeysFromSecret(secret) {
    const keyBytes = await hkdfExpandLabel(secret, 'quic key', new Uint8Array(0), 16, 'SHA-256');
    const iv = await hkdfExpandLabel(secret, 'quic iv', new Uint8Array(0), 12, 'SHA-256');
    const hpKeyBytes = await hkdfExpandLabel(secret, 'quic hp', new Uint8Array(0), 16, 'SHA-256');

    const key = await crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );

    return { key, keyBytes, iv, hpKeyBytes };
}

/**
 * TLS 1.2 PRF (Pseudo-Random Function) using HMAC-SHA256
 * P_hash(secret, seed) = HMAC(secret, A(1) + seed) + HMAC(secret, A(2) + seed) + ...
 * where A(0) = seed, A(i) = HMAC(secret, A(i-1))
 *
 * @param {Uint8Array} secret - The secret
 * @param {string} label - Label string
 * @param {Uint8Array} seed - Seed data
 * @param {number} length - Output length
 * @returns {Promise<Uint8Array>} Derived key material
 */
export async function tls12Prf(secret, label, seed, length) {
    const labelBytes = new TextEncoder().encode(label);
    const fullSeed = new Uint8Array(labelBytes.length + seed.length);
    fullSeed.set(labelBytes);
    fullSeed.set(seed, labelBytes.length);

    const hmacKey = await crypto.subtle.importKey(
        'raw',
        secret,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );

    const result = new Uint8Array(length);
    let offset = 0;

    // A(0) = seed
    let a = fullSeed;

    while (offset < length) {
        // A(i) = HMAC(secret, A(i-1))
        const aSig = await crypto.subtle.sign('HMAC', hmacKey, a);
        a = new Uint8Array(aSig);

        // P_hash += HMAC(secret, A(i) + seed)
        const input = new Uint8Array(a.length + fullSeed.length);
        input.set(a);
        input.set(fullSeed, a.length);

        const sig = await crypto.subtle.sign('HMAC', hmacKey, input);
        const chunk = new Uint8Array(sig);

        const toCopy = Math.min(chunk.length, length - offset);
        result.set(chunk.slice(0, toCopy), offset);
        offset += toCopy;
    }

    return result;
}
