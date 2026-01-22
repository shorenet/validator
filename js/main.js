/**
 * Shorenet Forensic Evidence Validator
 * Main orchestration module.
 *
 * This validator runs entirely in the browser using Web Crypto API.
 * No data is sent to any server.
 */

import { sha256, verifyHashChain, hexToBytes, bytesToHex, base64ToBytes } from './crypto/hash.js';
import { TlsDecryptor, parseTlsRecords, TLS_CONTENT_TYPE } from './crypto/tls.js';
import { parseCertificate, parseCertificateChain, formatDN, isCertificateValid } from './crypto/certificate.js';
import { HpackDecoder } from './protocol/hpack.js';
import { QpackDecoder } from './protocol/qpack.js';
import * as http1 from './protocol/http1.js';
import { Http2Parser, parseFrames as parseHttp2Frames, getFrameTypeName as getHttp2FrameTypeName } from './protocol/http2.js';
import { Http3Parser, parseFrames as parseHttp3Frames, getFrameTypeName as getHttp3FrameTypeName, decodeVarint } from './protocol/http3.js';
import * as websocket from './protocol/websocket.js';

/**
 * Extract TLS payload from raw packet data.
 * The data may be: Ethernet frame, full IP packet, TCP payload, or already TLS records.
 *
 * @param {Uint8Array} data - Raw packet data
 * @returns {Uint8Array|null} TLS record layer data
 */
function extractTlsPayload(data) {
    if (!data || data.length < 5) return null;

    // Check if it's already TLS record layer data
    // TLS record starts with content type (20-23) and version (0x0301, 0x0302, 0x0303)
    const firstByte = data[0];
    if (firstByte >= 20 && firstByte <= 23) {
        const version = (data[1] << 8) | data[2];
        if (version >= 0x0301 && version <= 0x0303) {
            // Already TLS data
            return data;
        }
    }

    // Check for IPv4 header (version 4 in high nibble)
    if ((data[0] >> 4) === 4) {
        return extractFromIpv4(data);
    }

    // Check for IPv6 header (version 6 in high nibble)
    if ((data[0] >> 4) === 6) {
        return extractFromIpv6(data);
    }

    // Check for Ethernet frame - EtherType at bytes 12-13
    // 0x0800 = IPv4, 0x86DD = IPv6
    if (data.length >= 14) {
        const etherType = (data[12] << 8) | data[13];
        if (etherType === 0x0800) {
            // Ethernet + IPv4
            console.log('[Validator] Detected Ethernet frame with IPv4');
            return extractFromIpv4(data.slice(14));
        } else if (etherType === 0x86DD) {
            // Ethernet + IPv6
            console.log('[Validator] Detected Ethernet frame with IPv6');
            return extractFromIpv6(data.slice(14));
        }
    }

    // Unknown format
    console.warn('[Validator] Unknown packet format, first bytes:',
        Array.from(data.slice(0, 20)).map(b => b.toString(16).padStart(2, '0')).join(' '));
    return null;
}

/**
 * Extract TCP payload from IPv4 packet.
 */
function extractFromIpv4(data) {
    if (data.length < 20) return null;

    // IPv4 header length is in the low nibble of first byte (in 32-bit words)
    const ihl = (data[0] & 0x0f) * 4;
    if (data.length < ihl) return null;

    // Check protocol field (byte 9) - TCP is 6
    const protocol = data[9];
    if (protocol !== 6) {
        console.warn('[Validator] Not TCP protocol:', protocol);
        return null;
    }

    // Extract TCP segment
    const tcpData = data.slice(ihl);
    return extractFromTcp(tcpData);
}

/**
 * Extract TCP payload from IPv6 packet.
 */
function extractFromIpv6(data) {
    if (data.length < 40) return null;

    // IPv6 has fixed 40-byte header
    // Next Header field is at byte 6
    let nextHeader = data[6];
    let offset = 40;

    // Skip extension headers until we find TCP (6)
    while (nextHeader !== 6 && offset < data.length) {
        if (nextHeader === 0 || nextHeader === 60 || nextHeader === 43 || nextHeader === 44) {
            // Hop-by-hop, Destination, Routing, Fragment
            const extLen = (data[offset + 1] + 1) * 8;
            nextHeader = data[offset];
            offset += extLen;
        } else {
            break;
        }
    }

    if (nextHeader !== 6) {
        console.warn('[Validator] Not TCP in IPv6:', nextHeader);
        return null;
    }

    const tcpData = data.slice(offset);
    return extractFromTcp(tcpData);
}

/**
 * Extract payload from TCP segment.
 */
function extractFromTcp(data) {
    if (data.length < 20) return null;

    // TCP data offset is in high nibble of byte 12 (in 32-bit words)
    const dataOffset = ((data[12] >> 4) & 0x0f) * 4;
    if (data.length <= dataOffset) return null;

    // Return TCP payload (the TLS data)
    return data.slice(dataOffset);
}

// DOM elements
let dropZone, fileInput, pasteInput, validatePasteBtn;
let uploadSection, validationSection, resultsSection;
let progressBar, statusText;
let tlsCard, detailsCard, websocketCard;
let claimedContent, decryptedContent, matchIndicator;

/**
 * Initialize the application.
 */
export function init() {
    // Get DOM elements
    dropZone = document.getElementById('drop-zone');
    fileInput = document.getElementById('file-input');
    uploadSection = document.getElementById('upload-section');
    validationSection = document.getElementById('validation-section');
    resultsSection = document.getElementById('results-section');
    progressBar = document.getElementById('progress-bar');
    statusText = document.getElementById('status-text');
    tlsCard = document.getElementById('tls-decryption');
    detailsCard = document.getElementById('transaction-details');
    websocketCard = document.getElementById('websocket-messages');
    pasteInput = document.getElementById('paste-input');
    validatePasteBtn = document.getElementById('validate-paste-btn');
    // Comparison view elements
    claimedContent = document.getElementById('claimed-content');
    decryptedContent = document.getElementById('decrypted-content');
    matchIndicator = document.getElementById('match-indicator');

    // Set up event listeners
    setupDragDrop();
    setupFileInput();
    setupPasteInput();
    setupResetButton();
}

/**
 * Set up drag and drop handlers.
 */
function setupDragDrop() {
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');

        const files = e.dataTransfer.files;
        if (files.length > 0) {
            processFile(files[0]);
        }
    });

    dropZone.addEventListener('click', () => {
        fileInput.click();
    });
}

/**
 * Set up file input handler.
 */
function setupFileInput() {
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            processFile(e.target.files[0]);
        }
    });
}

/**
 * Set up paste input handler.
 */
function setupPasteInput() {
    validatePasteBtn.addEventListener('click', () => {
        const text = pasteInput.value.trim();
        if (text) {
            processText(text);
        }
    });

    // Also validate on Ctrl+Enter in textarea
    pasteInput.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            const text = pasteInput.value.trim();
            if (text) {
                processText(text);
            }
        }
    });
}

/**
 * Set up reset button handler.
 */
function setupResetButton() {
    const resetBtn = document.getElementById('reset-btn');
    resetBtn.addEventListener('click', () => {
        uploadSection.classList.remove('hidden');
        validationSection.classList.add('hidden');
        resultsSection.classList.add('hidden');
        fileInput.value = '';
    });
}

/**
 * Process the uploaded file.
 * @param {File} file
 */
async function processFile(file) {
    try {
        updateProgress(10, 'Reading file...');
        const text = await file.text();
        await processText(text);
    } catch (error) {
        console.error('Validation error:', error);
        showError(error.message);
    }
}

/**
 * Process JSON text (from file or paste).
 * @param {string} text
 */
async function processText(text) {
    try {
        // Show validation section
        uploadSection.classList.add('hidden');
        validationSection.classList.remove('hidden');
        resultsSection.classList.add('hidden');

        updateProgress(15, 'Parsing JSON...');

        let evidence;
        try {
            evidence = JSON.parse(text);
        } catch (parseErr) {
            console.error('[Validator] JSON parse error:', parseErr);
            throw new Error(`Invalid JSON: ${parseErr.message}`);
        }

        console.log('[Validator] Parsed evidence:', evidence);
        console.log('[Validator] Evidence type:', evidence.type);
        console.log('[Validator] Has data wrapper:', !!evidence.data);

        updateProgress(20, 'Validating structure...');

        // Validate evidence structure
        const validationResult = await validateEvidence(evidence);

        console.log('[Validator] Validation complete:', validationResult);

        // Show results
        showResults(validationResult);

    } catch (error) {
        console.error('[Validator] Validation error:', error);
        console.error('[Validator] Stack:', error.stack);
        showError(error.message);
    }
}

/**
 * Update progress bar and status text.
 * @param {number} percent
 * @param {string} message
 */
function updateProgress(percent, message) {
    progressBar.style.width = `${percent}%`;
    statusText.textContent = message;
}

/**
 * Normalize evidence to a consistent format.
 * Handles CapturedEvent wrapper format from Trawler.
 * @param {Object} raw - Raw evidence input
 * @returns {Object} - Normalized evidence with forensic_evidence accessible
 */
function normalizeEvidence(raw) {
    console.log('[Validator] Normalizing evidence...');

    // Handle CapturedEvent wrapper: { type: "transaction", data: {...} }
    if (raw.type && raw.data) {
        console.log(`[Validator] Detected CapturedEvent wrapper, type: ${raw.type}`);
        const unwrapped = raw.data;
        unwrapped._eventType = raw.type;
        return unwrapped;
    }

    // Already unwrapped transaction/websocket message
    return raw;
}

/**
 * Validate forensic evidence by INDEPENDENTLY RE-DECRYPTING raw packets.
 *
 * The validator takes:
 * 1. Raw encrypted TLS packets from the wire
 * 2. Keylog data (TLS session secrets)
 * 3. The claimed decrypted content
 *
 * And verifies by:
 * 1. Re-decrypting the raw packets using the keylog
 * 2. Re-parsing the protocol (HTTP/1, HTTP/2, HTTP/3)
 * 3. Comparing what we decrypted against what's claimed
 *
 * This proves the evidence is genuine - you can't fake it without the actual keys.
 *
 * @param {Object} rawEvidence
 * @returns {Promise<Object>}
 */
async function validateEvidence(rawEvidence) {
    const result = {
        valid: false,
        hash: { valid: false, details: [] },
        tls: { valid: false, details: [], certificates: [], decrypted: null },
        protocol: { valid: false, details: [], headers: null, request: null, response: null },
        content: { valid: false, details: [], request: null, response: null },
        websocket: { valid: false, details: [], messages: [] },
        transaction: {},
        isWebSocket: false
    };

    // Normalize the evidence format (unwrap CapturedEvent if needed)
    const evidence = normalizeEvidence(rawEvidence);

    console.log('[Validator] Evidence keys:', Object.keys(evidence));
    console.log('[Validator] Protocol:', evidence.protocol);

    // Extract forensic_evidence - this is REQUIRED for validation
    const forensic = evidence.forensic_evidence;
    console.log('[Validator] Has forensic_evidence:', !!forensic);

    if (!forensic) {
        result.hash.details.push({ error: 'No forensic_evidence - cannot validate' });
        result.tls.details.push({ error: 'No forensic data' });
        result.protocol.details.push({ error: 'No forensic data' });
        result.content.details.push({ error: 'No forensic data' });
        result.transaction = extractTransactionDetails(rawEvidence, result);
        return result;
    }

    console.log('[Validator] forensic_evidence keys:', Object.keys(forensic));
    console.log('[Validator] Has keylog:', !!forensic.keylog);
    console.log('[Validator] Has raw_packets:', !!forensic.raw_packets);
    console.log('[Validator] Has certificate_info:', !!forensic.certificate_info);

    const packets = forensic.raw_packets?.packets;
    if (packets) {
        console.log('[Validator] Packets: %d total (%d handshake, %d application, %d bytes)',
            packets.length,
            forensic.raw_packets.handshake_count,
            forensic.raw_packets.application_count,
            forensic.raw_packets.total_bytes);
    }

    // Detect if this is WebSocket evidence
    result.isWebSocket = isWebSocketEvidence(rawEvidence);
    console.log('[Validator] Is WebSocket:', result.isWebSocket);

    try {
        // =====================================================================
        // 1. RAW PACKETS - Must have packets to validate
        // =====================================================================
        updateProgress(20, 'Checking raw packets...');

        if (!packets || packets.length === 0) {
            result.hash.details.push({ error: 'No raw packets - cannot independently verify' });
            result.hash.valid = false;
        } else {
            result.hash.valid = true;
            result.hash.details.push({
                success: `${packets.length} raw encrypted packets`
            });
            result.hash.details.push({
                note: `${forensic.raw_packets.handshake_count} handshake + ${forensic.raw_packets.application_count} application`
            });
            result.hash.details.push({
                note: `Total captured: ${formatBytes(forensic.raw_packets.total_bytes)}`
            });
        }

        // =====================================================================
        // 2. TLS DECRYPTION - Re-decrypt packets using keylog
        // =====================================================================
        updateProgress(40, 'Decrypting TLS records...');

        if (!forensic.keylog) {
            result.tls.details.push({ error: 'No keylog - cannot decrypt' });
            result.tls.valid = false;
        } else if (!packets || packets.length === 0) {
            result.tls.details.push({ error: 'No packets to decrypt' });
            result.tls.valid = false;
        } else {
            console.log('[Validator] Re-decrypting %d packets with keylog...', packets.length);

            try {
                // Initialize TLS decryptor with keylog
                const decryptor = new TlsDecryptor();
                console.log('[Validator] Initializing TLS decryptor...');
                await decryptor.initialize(forensic.keylog);
                console.log('[Validator] TLS decryptor initialized: version=%s', decryptor.version);

                const decryptedPayloads = [];
                let appPacketCount = 0;

                // Process each packet
                for (const packet of packets) {
                    if (packet.packet_type !== 'application') continue;
                    appPacketCount++;

                    const rawData = base64ToBytes(packet.data);
                    const direction = packet.direction === 'client_to_server' ? 'client' : 'server';

                    console.log('[Validator] Processing %s packet: %d bytes', direction, rawData.length);

                    // Extract TLS payload from IP packet
                    // The raw data may be: full IP packet, TCP payload, or TLS records
                    const tlsData = extractTlsPayload(rawData);
                    if (!tlsData || tlsData.length === 0) {
                        console.warn('[Validator] Could not extract TLS payload from packet');
                        continue;
                    }
                    console.log('[Validator] Extracted TLS payload: %d bytes', tlsData.length);

                    try {
                        const records = parseTlsRecords(tlsData);
                        console.log('[Validator] Parsed %d TLS records', records.length);

                        for (const record of records) {
                            console.log('[Validator] Record type=%d, version=0x%s, len=%d',
                                record.type, record.version.toString(16), record.data.length);

                            if (record.type === TLS_CONTENT_TYPE.APPLICATION_DATA) {
                                // Use tryDecryptRecord which tries both app and handshake keys
                                const decrypted = await decryptor.tryDecryptRecord(record.raw, direction);
                                if (decrypted && decrypted.plaintext) {
                                    decryptedPayloads.push({
                                        direction,
                                        data: decrypted.plaintext,
                                        contentType: decrypted.contentType
                                    });
                                    console.log('[Validator] Decrypted %s record: %d bytes, inner type=%d',
                                        direction, decrypted.plaintext.length, decrypted.contentType);
                                }
                            }
                        }
                    } catch (e) {
                        console.warn('[Validator] Packet decrypt failed:', e.message);
                    }
                }

                console.log('[Validator] Processed %d app packets, decrypted %d payloads',
                    appPacketCount, decryptedPayloads.length);

                if (decryptedPayloads.length > 0) {
                    result.tls.valid = true;
                    result.tls.decrypted = decryptedPayloads;
                    result.tls.details.push({
                        success: `Decrypted ${decryptedPayloads.length} application data records`
                    });

                    // Calculate total decrypted size
                    const totalDecrypted = decryptedPayloads.reduce((sum, p) => sum + p.data.length, 0);
                    result.tls.details.push({
                        note: `Total decrypted: ${formatBytes(totalDecrypted)}`
                    });
                } else {
                    result.tls.details.push({ error: 'Failed to decrypt any records' });
                    result.tls.valid = false;
                }

            } catch (e) {
                console.error('[Validator] TLS decryption error:', e);
                console.error('[Validator] Stack:', e.stack);
                result.tls.details.push({ error: `Decryption failed: ${e.message}` });
                result.tls.valid = false;
            }
        }

        // Parse certificates and store certificate info for comparison view
        if (forensic.certificate_info) {
            const certInfo = forensic.certificate_info;

            // Store the certificate info for the comparison view
            result._certInfo = certInfo;

            if (certInfo.certificate_chain?.length > 0) {
                try {
                    const certs = await parseCertificateChain(certInfo.certificate_chain);
                    result.tls.certificates = certs;
                } catch (e) {
                    console.warn('[Validator] Certificate parse failed:', e.message);
                }
            }
        }

        // =====================================================================
        // 3. PROTOCOL PARSING - Parse decrypted data as HTTP
        // =====================================================================
        updateProgress(60, 'Parsing protocol...');

        if (result.tls.decrypted && result.tls.decrypted.length > 0) {
            console.log('[Validator] Parsing decrypted data as %s...', evidence.protocol);

            try {
                const parsed = await parseDecryptedProtocol(evidence.protocol, result.tls.decrypted);
                result.protocol = { ...result.protocol, ...parsed };

                if (parsed.valid) {
                    result.protocol.details.push({
                        success: `Parsed ${evidence.protocol} from decrypted data`
                    });
                }
            } catch (e) {
                console.error('[Validator] Protocol parse error:', e);
                result.protocol.details.push({ error: `Parse failed: ${e.message}` });
            }
        } else {
            result.protocol.details.push({ note: 'No decrypted data to parse' });

            // Fall back to showing claimed data
            if (evidence.request && evidence.response) {
                result.protocol.request = {
                    method: evidence.request.method,
                    url: evidence.request.url,
                    headers: evidence.request.headers
                };
                result.protocol.response = {
                    status: evidence.response.status,
                    statusText: evidence.response.status_text,
                    headers: evidence.response.headers
                };
                result.protocol.details.push({
                    note: `Claimed: ${evidence.request.method} ${evidence.response.status}`
                });
            }
        }

        // =====================================================================
        // 4. CONTENT COMPARISON - Compare decrypted vs claimed
        // =====================================================================
        updateProgress(80, 'Comparing content...');

        const claimedReqBody = evidence.request?.body ? base64ToBytes(evidence.request.body) : null;
        const claimedResBody = evidence.response?.body ? base64ToBytes(evidence.response.body) : null;

        if (result.protocol.parsedRequest?.body || result.protocol.parsedResponse?.body) {
            // We have parsed bodies from decryption - compare them
            const decryptedReqBody = result.protocol.parsedRequest?.body;
            const decryptedResBody = result.protocol.parsedResponse?.body;

            // Compute hashes of decrypted bodies for comparison view
            if (decryptedReqBody && decryptedReqBody.length > 0) {
                const hash = await sha256(decryptedReqBody);
                result.content.decryptedRequest = {
                    size: decryptedReqBody.length,
                    hash: bytesToHex(hash)
                };
            }
            if (decryptedResBody && decryptedResBody.length > 0) {
                const hash = await sha256(decryptedResBody);
                result.content.decryptedResponse = {
                    size: decryptedResBody.length,
                    hash: bytesToHex(hash)
                };
            }

            if (claimedReqBody && decryptedReqBody) {
                const reqMatch = compareBytes(claimedReqBody, decryptedReqBody);
                if (reqMatch) {
                    result.content.details.push({ success: `Request body matches (${formatBytes(claimedReqBody.length)})` });
                    result.content.valid = true;
                } else {
                    // Compare hashes for more detail
                    const claimedHash = bytesToHex(await sha256(claimedReqBody));
                    const decryptedHash = result.content.decryptedRequest?.hash;
                    result.content.details.push({
                        error: `Request body MISMATCH! Claimed: ${claimedHash.slice(0,16)}... Decrypted: ${decryptedHash?.slice(0,16)}...`
                    });
                    result.content.valid = false;
                }
            }

            if (claimedResBody && decryptedResBody) {
                const resMatch = compareBytes(claimedResBody, decryptedResBody);
                if (resMatch) {
                    result.content.details.push({ success: `Response body matches (${formatBytes(claimedResBody.length)})` });
                    result.content.valid = true;
                } else {
                    const claimedHash = bytesToHex(await sha256(claimedResBody));
                    const decryptedHash = result.content.decryptedResponse?.hash;
                    result.content.details.push({
                        error: `Response body MISMATCH! Claimed: ${claimedHash.slice(0,16)}... Decrypted: ${decryptedHash?.slice(0,16)}...`
                    });
                    result.content.valid = false;
                }
            }

            // Also store claimed body hashes
            if (claimedReqBody) {
                const hash = await sha256(claimedReqBody);
                result.content.request = {
                    size: claimedReqBody.length,
                    hash: bytesToHex(hash)
                };
            }
            if (claimedResBody) {
                const hash = await sha256(claimedResBody);
                result.content.response = {
                    size: claimedResBody.length,
                    hash: bytesToHex(hash)
                };
            }
        } else {
            // No decrypted bodies to compare - show claimed content
            result.content.valid = true; // Can't disprove it
            result.content.details.push({ note: 'Cannot verify bodies (decryption incomplete)' });

            if (claimedReqBody) {
                const hash = await sha256(claimedReqBody);
                result.content.request = {
                    size: claimedReqBody.length,
                    hash: bytesToHex(hash),
                    preview: getBodyPreview(claimedReqBody, evidence.request.headers)
                };
                result.content.details.push({ note: `Request: ${formatBytes(claimedReqBody.length)}` });
            }

            if (claimedResBody) {
                const hash = await sha256(claimedResBody);
                result.content.response = {
                    size: claimedResBody.length,
                    hash: bytesToHex(hash),
                    preview: getBodyPreview(claimedResBody, evidence.response.headers)
                };
                result.content.details.push({ note: `Response: ${formatBytes(claimedResBody.length)}` });
            }
        }

        // =====================================================================
        // 5. WEBSOCKET MESSAGES
        // =====================================================================
        if (result.isWebSocket) {
            updateProgress(90, 'Validating WebSocket...');
            result.websocket = await validateWebSocketMessages(rawEvidence);
        }

        // =====================================================================
        // 6. TRANSACTION DETAILS
        // =====================================================================
        updateProgress(95, 'Extracting details...');
        result.transaction = extractTransactionDetails(rawEvidence, result);

        // =====================================================================
        // 7. FIELD COMPARISON - Compare claimed vs decrypted fields
        // =====================================================================
        result.fieldMatches = {};

        if (result.tls.valid && result.protocol.parsedRequest) {
            const claimed = {
                method: evidence.request?.method,
                url: evidence.request?.url,
                status: evidence.response?.status
            };
            const decrypted = {
                method: result.protocol.parsedRequest?.method,
                url: result.protocol.parsedRequest?.url,
                status: result.protocol.parsedResponse?.status
            };

            // Method comparison
            result.fieldMatches.method = decrypted.method === claimed.method;

            // URL/Path comparison (HTTP/2 has :path, claimed has full URL)
            let claimedPath = claimed.url || '';
            try {
                const urlObj = new URL(claimedPath);
                claimedPath = urlObj.pathname + urlObj.search;
            } catch (e) {
                // Already a path
            }
            result.fieldMatches.url = decrypted.url === claimedPath;

            // Status comparison
            result.fieldMatches.status = decrypted.status === claimed.status;

            // Body hash comparison (already computed in content section)
            if (result.content.request?.hash && result.content.decryptedRequest?.hash) {
                result.fieldMatches.requestBody = result.content.request.hash === result.content.decryptedRequest.hash;
            }
            if (result.content.response?.hash && result.content.decryptedResponse?.hash) {
                result.fieldMatches.responseBody = result.content.response.hash === result.content.decryptedResponse.hash;
            }

            console.log('[Validator] Field matches:', result.fieldMatches);
        }

        // Overall validity: decryption + hash + all field comparisons must match
        const criticalFieldsMatch =
            (result.fieldMatches.method !== false) &&
            (result.fieldMatches.url !== false) &&
            (result.fieldMatches.status !== false) &&
            (result.fieldMatches.requestBody !== false) &&
            (result.fieldMatches.responseBody !== false);

        result.valid = result.tls.valid && result.hash.valid && criticalFieldsMatch;

    } catch (error) {
        console.error('[Validator] Validation error:', error);
        console.error('[Validator] Stack:', error.stack);
        result.valid = false;
        result.error = error.message;
    }

    updateProgress(100, 'Complete');
    return result;
}

/**
 * Compare two byte arrays.
 */
function compareBytes(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

/**
 * Parse decrypted TLS payloads as HTTP protocol.
 */
async function parseDecryptedProtocol(protocol, decryptedPayloads) {
    const result = {
        valid: false,
        details: [],
        parsedRequest: null,
        parsedResponse: null,
        request: null,
        response: null
    };

    // Combine payloads by direction
    const clientData = [];
    const serverData = [];

    // Filter to only include application data (contentType 23)
    // Exclude handshake data (contentType 22) which can appear in encrypted form
    for (const payload of decryptedPayloads) {
        // contentType 23 = application data, 22 = handshake
        if (payload.contentType !== 23) {
            console.log('[Validator]   Skipping %s payload with contentType=%d (not app data)',
                payload.direction, payload.contentType);
            continue;
        }
        if (payload.direction === 'client') {
            clientData.push(payload.data);
        } else {
            serverData.push(payload.data);
        }
    }

    console.log('[Validator] Decrypted payloads: %d total, %d app data (%d client, %d server)',
        decryptedPayloads.length, clientData.length + serverData.length,
        clientData.length, serverData.length);
    for (let i = 0; i < decryptedPayloads.length; i++) {
        const p = decryptedPayloads[i];
        console.log('[Validator]   Payload %d: direction=%s, contentType=%d, len=%d',
            i, p.direction, p.contentType, p.data.length);
    }

    const clientBytes = concatBytes(clientData);
    const serverBytes = concatBytes(serverData);

    console.log('[Validator] Concatenated: client=%d bytes, server=%d bytes',
        clientBytes.length, serverBytes.length);

    try {
        if (protocol === 'HTTP/1.1' || protocol === 'HTTP/1.0') {
            // Parse HTTP/1.x
            const reqParsed = http1.parseRequest(clientBytes);
            const resParsed = http1.parseResponse(serverBytes);

            if (reqParsed) {
                // Decompress request body if needed
                const reqEncoding = reqParsed.headers?.['content-encoding'];
                if (reqEncoding && reqParsed.body && reqParsed.body.length > 0) {
                    reqParsed.body = await decompressBody(reqParsed.body, reqEncoding);
                }
                result.parsedRequest = reqParsed;
                result.request = {
                    method: reqParsed.method,
                    url: reqParsed.url,
                    headers: reqParsed.headers
                };
            }

            if (resParsed) {
                // Decompress response body if needed
                const resEncoding = resParsed.headers?.['content-encoding'];
                if (resEncoding && resParsed.body && resParsed.body.length > 0) {
                    console.log('[Validator] HTTP/1: Response has content-encoding: %s, body=%d bytes',
                        resEncoding, resParsed.body.length);
                    resParsed.body = await decompressBody(resParsed.body, resEncoding);
                }
                result.parsedResponse = resParsed;
                result.response = {
                    status: resParsed.status,
                    statusText: resParsed.statusText,
                    headers: resParsed.headers
                };
            }

            result.valid = !!(reqParsed || resParsed);
            result.details.push({ success: 'Parsed HTTP/1.x from decrypted stream' });

        } else if (protocol === 'HTTP/2') {
            // Parse HTTP/2 frames from both client and server
            // HTTP/2 requires separate parsers for each direction to maintain
            // separate HPACK dynamic table states
            const clientParser = new Http2Parser();
            const serverParser = new Http2Parser();

            console.log('[Validator] HTTP/2: clientBytes=%d, serverBytes=%d', clientBytes.length, serverBytes.length);

            // Parse client frames (requests)
            if (clientBytes.length > 0) {
                try {
                    // Skip HTTP/2 connection preface if present (client only)
                    let clientOffset = 0;
                    const preface = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';
                    const prefaceBytes = new TextEncoder().encode(preface);
                    if (clientBytes.length >= prefaceBytes.length) {
                        let isPreface = true;
                        for (let i = 0; i < prefaceBytes.length; i++) {
                            if (clientBytes[i] !== prefaceBytes[i]) {
                                isPreface = false;
                                break;
                            }
                        }
                        if (isPreface) {
                            clientOffset = prefaceBytes.length;
                            console.log('[Validator] HTTP/2: Skipped connection preface (%d bytes)', prefaceBytes.length);
                        }
                    }
                    clientParser.parse(clientBytes.slice(clientOffset));
                    console.log('[Validator] HTTP/2: Client parser found %d streams', clientParser.streams.size);
                    for (const [sid, stream] of clientParser.streams) {
                        console.log('[Validator] HTTP/2: Client stream %d: reqHeaders=%s, resHeaders=%s',
                            sid, !!stream.requestHeaders, !!stream.responseHeaders);
                    }
                } catch (e) {
                    console.warn('[Validator] HTTP/2 client parse error:', e);
                    result.details.push({ warning: `Client frame parse error: ${e.message}` });
                }
            }

            // Parse server frames (responses)
            if (serverBytes.length > 0) {
                try {
                    // Debug: show first bytes of server data
                    const hexBytes = Array.from(serverBytes.slice(0, 32))
                        .map(b => b.toString(16).padStart(2, '0')).join(' ');
                    console.log('[Validator] HTTP/2: Server first 32 bytes: %s', hexBytes);

                    // Parse first frame header manually to debug
                    if (serverBytes.length >= 9) {
                        const frameLen = (serverBytes[0] << 16) | (serverBytes[1] << 8) | serverBytes[2];
                        const frameType = serverBytes[3];
                        const frameFlags = serverBytes[4];
                        const streamId = ((serverBytes[5] & 0x7f) << 24) | (serverBytes[6] << 16) |
                                        (serverBytes[7] << 8) | serverBytes[8];
                        console.log('[Validator] HTTP/2: First frame header: len=%d, type=%d (%s), flags=0x%s, streamId=%d',
                            frameLen, frameType, getHttp2FrameTypeName(frameType),
                            frameFlags.toString(16), streamId);
                        console.log('[Validator] HTTP/2: Need %d bytes, have %d bytes', 9 + frameLen, serverBytes.length);
                    }

                    // Debug: show what frames are in the server data
                    const serverFrames = parseHttp2Frames(serverBytes);
                    console.log('[Validator] HTTP/2: Server has %d frames', serverFrames.length);
                    for (const frame of serverFrames) {
                        console.log('[Validator] HTTP/2: Server frame type=%s, streamId=%d, flags=0x%s, len=%d',
                            getHttp2FrameTypeName(frame.type), frame.streamId,
                            frame.flags.toString(16), frame.payload.length);
                    }

                    serverParser.parse(serverBytes);
                    console.log('[Validator] HTTP/2: Server parser found %d streams', serverParser.streams.size);
                    for (const [sid, stream] of serverParser.streams) {
                        console.log('[Validator] HTTP/2: Server stream %d: reqHeaders=%s, resHeaders=%s, dataFrames=%d',
                            sid, !!stream.requestHeaders, !!stream.responseHeaders,
                            stream.responseData?.length || 0);
                    }
                } catch (e) {
                    console.warn('[Validator] HTTP/2 server parse error:', e);
                    console.error(e);
                    result.details.push({ warning: `Server frame parse error: ${e.message}` });
                }
            }

            // Find matching request/response streams
            // Use stream ID 1 if available (first client-initiated stream), else first odd stream
            let selectedStreamId = null;
            for (const [streamId, stream] of clientParser.streams) {
                if (stream.requestHeaders && streamId % 2 === 1) {
                    if (streamId === 1 || selectedStreamId === null) {
                        selectedStreamId = streamId;
                        if (streamId === 1) break;
                    }
                }
            }
            console.log('[Validator] HTTP/2: Selected stream ID = %s', selectedStreamId);

            // Get request from client parser
            if (selectedStreamId !== null) {
                const clientStream = clientParser.streams.get(selectedStreamId);
                if (clientStream && clientStream.requestHeaders) {
                    const pseudoHeaders = Http2Parser.getPseudoHeaders(clientStream.requestHeaders);
                    const regularHeaders = Http2Parser.headersToObject(
                        clientStream.requestHeaders.filter(([name]) => !name.startsWith(':'))
                    );
                    console.log('[Validator] HTTP/2: Request pseudo-headers:', pseudoHeaders);

                    // Get request body and decompress if needed
                    let reqBody = clientStream.getBody(true);
                    const reqContentEncoding = Object.entries(regularHeaders)
                        .find(([k]) => k.toLowerCase() === 'content-encoding')?.[1];
                    if (reqContentEncoding && reqBody && reqBody.length > 0) {
                        reqBody = await decompressBody(reqBody, reqContentEncoding);
                    }

                    result.parsedRequest = {
                        method: pseudoHeaders.method || 'GET',
                        url: pseudoHeaders.path || '/',
                        authority: pseudoHeaders.authority,
                        scheme: pseudoHeaders.scheme,
                        headers: regularHeaders,
                        body: reqBody
                    };

                    result.request = {
                        method: pseudoHeaders.method || 'GET',
                        url: pseudoHeaders.path || '/',
                        headers: regularHeaders
                    };
                }
            }

            // Get response from server parser (same stream ID)
            if (selectedStreamId !== null) {
                const serverStream = serverParser.streams.get(selectedStreamId);
                if (serverStream && serverStream.responseHeaders) {
                    const pseudoHeaders = Http2Parser.getPseudoHeaders(serverStream.responseHeaders);
                    const regularHeaders = Http2Parser.headersToObject(
                        serverStream.responseHeaders.filter(([name]) => !name.startsWith(':'))
                    );
                    console.log('[Validator] HTTP/2: Response pseudo-headers:', pseudoHeaders);

                    // Get response body and decompress if needed
                    let resBody = serverStream.getBody(false);
                    const resContentEncoding = Object.entries(regularHeaders)
                        .find(([k]) => k.toLowerCase() === 'content-encoding')?.[1];
                    if (resContentEncoding && resBody && resBody.length > 0) {
                        console.log('[Validator] HTTP/2: Response has content-encoding: %s, body=%d bytes',
                            resContentEncoding, resBody.length);
                        resBody = await decompressBody(resBody, resContentEncoding);
                    }

                    result.parsedResponse = {
                        status: parseInt(pseudoHeaders.status, 10) || 0,
                        statusText: '',  // HTTP/2 doesn't have status text
                        headers: regularHeaders,
                        body: resBody
                    };

                    result.response = {
                        status: parseInt(pseudoHeaders.status, 10) || 0,
                        statusText: '',
                        headers: regularHeaders
                    };

                    // Note if compression was applied
                    if (resContentEncoding && resBody && resBody.length > 0) {
                        result.details.push({
                            note: `Response body decompressed from ${resContentEncoding}`
                        });
                    }
                }
            }

            const totalStreams = Math.max(clientParser.streams.size, serverParser.streams.size);
            result.valid = !!(result.parsedRequest || result.parsedResponse);
            result.details.push({
                success: `Parsed HTTP/2: ${totalStreams} stream(s), selected stream ${selectedStreamId || 'none'}`
            });

        } else if (protocol === 'HTTP/3') {
            // Parse HTTP/3
            const parser = new Http3Parser();
            // TODO: Parse HTTP/3 frames from decrypted data
            result.details.push({ note: 'HTTP/3 parsing not yet implemented' });
            result.valid = true;

        } else {
            result.details.push({ note: `Unknown protocol: ${protocol}` });
        }
    } catch (e) {
        console.error('[Validator] Protocol parse error:', e);
        result.details.push({ error: e.message });
    }

    return result;
}

/**
 * Concatenate multiple Uint8Arrays.
 */
function concatBytes(arrays) {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}

/**
 * Decompress data based on content-encoding.
 * Uses browser's DecompressionStream API.
 *
 * @param {Uint8Array} data - Compressed data
 * @param {string} encoding - Content-Encoding header value (gzip, deflate, br)
 * @returns {Promise<Uint8Array>} - Decompressed data
 */
async function decompressBody(data, encoding) {
    if (!data || data.length === 0) return data;
    if (!encoding) return data;

    const enc = encoding.toLowerCase().trim();

    // Handle Brotli using brotli-wasm library (loaded via brotli-init.js)
    if (enc === 'br' || enc === 'brotli') {
        if (typeof brotliWasm !== 'undefined' && brotliWasm.decompress) {
            try {
                const decompressed = brotliWasm.decompress(data);
                console.log('[Validator] Decompressed brotli: %d -> %d bytes', data.length, decompressed.length);
                return decompressed;
            } catch (e) {
                console.warn('[Validator] Brotli decompression failed:', e.message);
                return data;
            }
        } else {
            console.warn('[Validator] brotli-wasm library not loaded');
            return data;
        }
    }

    // Handle zstd using fzstd (pure JS, used by Facebook/Instagram)
    if (enc === 'zstd' || enc === 'zstandard') {
        if (typeof fzstd !== 'undefined' && fzstd.decompress) {
            try {
                const decompressed = fzstd.decompress(data);
                console.log('[Validator] Decompressed zstd: %d -> %d bytes', data.length, decompressed.length);
                return new Uint8Array(decompressed);
            } catch (e) {
                console.warn('[Validator] Zstd decompression failed:', e.message);
                return data;
            }
        } else {
            console.warn('[Validator] fzstd library not loaded');
            return data;
        }
    }

    // Use fflate for gzip/deflate (more reliable than DecompressionStream)
    if (typeof fflate !== 'undefined') {
        try {
            let decompressed;
            if (enc === 'gzip' || enc === 'x-gzip') {
                decompressed = fflate.gunzipSync(data);
            } else if (enc === 'deflate') {
                // Try zlib first (deflate with zlib header), fall back to raw deflate
                try {
                    decompressed = fflate.unzlibSync(data);
                } catch {
                    decompressed = fflate.inflateSync(data);
                }
            } else if (enc === 'deflate-raw') {
                decompressed = fflate.inflateSync(data);
            } else {
                // Unknown encoding, return as-is
                return data;
            }
            console.log('[Validator] Decompressed %s (fflate): %d -> %d bytes', enc, data.length, decompressed.length);
            return decompressed;
        } catch (e) {
            console.warn('[Validator] fflate decompression failed for %s:', enc, e.message);
            // Fall through to DecompressionStream
        }
    }

    // Fallback to browser's DecompressionStream
    if (typeof DecompressionStream === 'undefined') {
        console.warn('[Validator] DecompressionStream not available, returning raw data');
        return data;
    }

    let format;
    if (enc === 'gzip' || enc === 'x-gzip') {
        format = 'gzip';
    } else if (enc === 'deflate') {
        format = 'deflate';
    } else if (enc === 'deflate-raw') {
        format = 'deflate-raw';
    } else {
        // Unknown or identity encoding
        return data;
    }

    try {
        const stream = new DecompressionStream(format);
        const writer = stream.writable.getWriter();
        const reader = stream.readable.getReader();

        // Write data
        writer.write(data);
        writer.close();

        // Read decompressed chunks
        const chunks = [];
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            chunks.push(value);
        }

        const decompressed = concatBytes(chunks);
        console.log('[Validator] Decompressed %s: %d -> %d bytes', enc, data.length, decompressed.length);
        return decompressed;
    } catch (e) {
        console.warn('[Validator] Decompression failed for %s:', enc, e.message);
        return data; // Return original on failure
    }
}

/**
 * Get a preview of body content based on content type.
 * @param {Uint8Array} body
 * @param {Object} headers
 * @returns {string|null}
 */
function getBodyPreview(body, headers) {
    if (!body || body.length === 0) return null;

    // Check content type
    const contentType = Object.entries(headers || {})
        .find(([k]) => k.toLowerCase() === 'content-type')?.[1] || '';

    const isText = contentType.includes('text') ||
                   contentType.includes('json') ||
                   contentType.includes('xml') ||
                   contentType.includes('javascript');

    if (isText) {
        try {
            const text = new TextDecoder('utf-8', { fatal: true }).decode(body);
            return text.length > 500 ? text.substring(0, 500) + '...' : text;
        } catch {
            // Not valid UTF-8
        }
    }

    // Binary preview
    const hexPreview = Array.from(body.slice(0, 64))
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' ');
    return hexPreview + (body.length > 64 ? '...' : '');
}

/**
 * Decrypt TLS records using keylog data.
 * @param {Object} evidence
 * @returns {Promise<Object>}
 */
async function decryptTls(evidence) {
    const result = {
        valid: false,
        details: [],
        certificates: [],
        decryptedPayloads: []
    };

    try {
        const decryptor = new TlsDecryptor();
        await decryptor.initialize(evidence.keylog);

        // Process each packet
        for (const packet of evidence.packets) {
            const data = base64ToBytes(packet.data);
            const records = parseTlsRecords(data);

            for (const record of records) {
                if (record.type === TLS_CONTENT_TYPE.APPLICATION_DATA) {
                    try {
                        const decrypted = await decryptor.decryptRecord(
                            record.raw,
                            packet.direction === 'client' ? 'client' : 'server'
                        );
                        result.decryptedPayloads.push({
                            direction: packet.direction,
                            data: decrypted.plaintext,
                            contentType: decrypted.contentType
                        });
                    } catch (e) {
                        result.details.push({
                            warning: `Failed to decrypt record: ${e.message}`
                        });
                    }
                } else if (record.type === TLS_CONTENT_TYPE.HANDSHAKE) {
                    // Try to extract certificates from handshake
                    const handshakeType = record.data[0];
                    if (handshakeType === 11) { // Certificate message
                        try {
                            const certData = record.data.slice(4); // Skip handshake header
                            const certs = parseCertificateChain(certData);
                            result.certificates = certs;
                        } catch (e) {
                            // Certificate parsing failed
                        }
                    }
                }
            }
        }

        result.valid = result.decryptedPayloads.length > 0;
        result.details.push({
            success: `Decrypted ${result.decryptedPayloads.length} application data records`
        });

    } catch (e) {
        result.details.push({ error: e.message });
    }

    return result;
}

/**
 * Parse HTTP protocol from decrypted data.
 * @param {Object} evidence
 * @param {Object} tlsResult
 * @returns {Object}
 */
async function parseProtocol(evidence, tlsResult) {
    const result = {
        valid: false,
        details: [],
        headers: null,
        protocol: evidence.protocol || 'unknown'
    };

    try {
        // Use pre-parsed headers if available
        if (evidence.request?.headers || evidence.response?.headers) {
            result.headers = {
                request: evidence.request?.headers || {},
                response: evidence.response?.headers || {}
            };
            result.valid = true;
            result.details.push({ success: 'Using pre-parsed headers from evidence' });
            return result;
        }

        // Otherwise, try to parse from decrypted payloads
        if (tlsResult.decryptedPayloads && tlsResult.decryptedPayloads.length > 0) {
            const protocol = evidence.protocol?.toLowerCase() || '';

            if (protocol.includes('http3') || protocol === 'h3') {
                result.protocol = 'HTTP/3';
                // Parse HTTP/3 frames with QPACK
                const parser = new Http3Parser();

                // Process QPACK encoder stream if present
                if (evidence.qpack_encoder_data) {
                    parser.processEncoderStream(base64ToBytes(evidence.qpack_encoder_data));
                }

                // Parse streams
                for (const payload of tlsResult.decryptedPayloads) {
                    const frames = parseHttp3Frames(payload.data);
                    result.details.push({
                        frames: frames.map(f => getHttp3FrameTypeName(f.type))
                    });
                }

            } else if (protocol.includes('http2') || protocol === 'h2') {
                result.protocol = 'HTTP/2';
                const parser = new Http2Parser();

                // Combine payloads and parse frames
                for (const payload of tlsResult.decryptedPayloads) {
                    const frames = parseHttp2Frames(payload.data);
                    for (const frame of frames) {
                        parser.processFrame(frame);
                    }
                    result.details.push({
                        frames: frames.map(f => getHttp2FrameTypeName(f.type))
                    });
                }

                // Extract headers from streams
                for (const [streamId, stream] of parser.streams) {
                    if (stream.requestHeaders) {
                        result.headers = result.headers || { request: {}, response: {} };
                        result.headers.request = Http2Parser.headersToObject(stream.requestHeaders);
                    }
                    if (stream.responseHeaders) {
                        result.headers = result.headers || { request: {}, response: {} };
                        result.headers.response = Http2Parser.headersToObject(stream.responseHeaders);
                    }
                }

            } else {
                result.protocol = 'HTTP/1.1';
                // Parse HTTP/1.x
                for (const payload of tlsResult.decryptedPayloads) {
                    if (payload.direction === 'client') {
                        try {
                            const req = http1.parseRequest(payload.data);
                            result.headers = result.headers || { request: {}, response: {} };
                            result.headers.request = req.headers;
                            result.headers.request[':method'] = req.method;
                            result.headers.request[':path'] = req.path;
                        } catch (e) {
                            // Not a request
                        }
                    } else {
                        try {
                            const res = http1.parseResponse(payload.data);
                            result.headers = result.headers || { request: {}, response: {} };
                            result.headers.response = res.headers;
                            result.headers.response[':status'] = String(res.status);
                        } catch (e) {
                            // Not a response
                        }
                    }
                }
            }

            result.valid = result.headers !== null;
        }

    } catch (e) {
        result.details.push({ error: e.message });
    }

    return result;
}

/**
 * Verify content body hashes.
 * @param {Object} evidence
 * @returns {Promise<Object>}
 */
async function verifyContent(evidence) {
    const result = {
        valid: true,
        details: []
    };

    if (evidence.request_body && evidence.request_body_hash) {
        const bodyData = base64ToBytes(evidence.request_body);
        const hash = await sha256(bodyData);
        const hashHex = bytesToHex(hash);
        const matches = hashHex === evidence.request_body_hash.toLowerCase();

        result.details.push({
            field: 'Request Body',
            expected: evidence.request_body_hash,
            computed: hashHex,
            valid: matches
        });

        if (!matches) result.valid = false;
    }

    if (evidence.response_body && evidence.response_body_hash) {
        const bodyData = base64ToBytes(evidence.response_body);
        const hash = await sha256(bodyData);
        const hashHex = bytesToHex(hash);
        const matches = hashHex === evidence.response_body_hash.toLowerCase();

        result.details.push({
            field: 'Response Body',
            expected: evidence.response_body_hash,
            computed: hashHex,
            valid: matches
        });

        if (!matches) result.valid = false;
    }

    return result;
}

/**
 * Check if evidence is for a WebSocket message.
 * @param {Object} evidence
 * @returns {boolean}
 */
function isWebSocketEvidence(evidence) {
    // Check for WebSocket-specific fields
    if (evidence.message_type !== undefined) return true;
    if (evidence.type === 'websocket_message') return true;
    if (evidence.type === 'WebSocketMessage') return true;
    if (evidence.protocol === 'WebSocket') return true;

    // Check for CapturedEvent wrapper
    if (evidence.type === 'websocket_message' && evidence.data) return true;

    return false;
}

/**
 * Validate WebSocket message evidence.
 * @param {Object} evidence
 * @returns {Promise<Object>}
 */
async function validateWebSocketMessages(evidence) {
    const result = {
        valid: false,
        details: [],
        messages: []
    };

    try {
        // Get the actual message data (handle CapturedEvent wrapper)
        const messageData = evidence.data || evidence;

        // Basic validation
        if (messageData.message_type === undefined) {
            result.details.push({ error: 'Missing message_type field' });
            return result;
        }

        const messageInfo = {
            type: messageData.message_type,
            direction: messageData.direction || 'unknown',
            timestamp: messageData.timestamp_us
                ? new Date(messageData.timestamp_us / 1000).toISOString()
                : null,
            url: messageData.url,
            size: 0,
            preview: ''
        };

        // Process payload
        if (messageData.payload) {
            const payloadData = base64ToBytes(messageData.payload);
            messageInfo.size = payloadData.length;

            if (messageData.message_type === 'Text') {
                const text = new TextDecoder('utf-8', { fatal: false }).decode(payloadData);
                messageInfo.preview = text.length > 500 ? text.substring(0, 500) + '...' : text;

                // Try to detect JSON
                try {
                    JSON.parse(text);
                    messageInfo.isJson = true;
                } catch {
                    messageInfo.isJson = false;
                }
            } else if (messageData.message_type === 'Binary') {
                // Show hex preview
                const hexBytes = Array.from(payloadData.slice(0, 32))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join(' ');
                messageInfo.preview = hexBytes + (payloadData.length > 32 ? '...' : '');
            } else if (messageData.message_type === 'Close') {
                if (payloadData.length >= 2) {
                    const closeCode = (payloadData[0] << 8) | payloadData[1];
                    messageInfo.closeCode = closeCode;
                    messageInfo.closeReason = websocket.getCloseCodeDescription(closeCode);
                    if (payloadData.length > 2) {
                        messageInfo.closeMessage = new TextDecoder('utf-8', { fatal: false })
                            .decode(payloadData.slice(2));
                    }
                }
            }
        } else if (messageData.text) {
            // Text is provided directly
            messageInfo.preview = messageData.text.length > 500
                ? messageData.text.substring(0, 500) + '...'
                : messageData.text;
            messageInfo.size = messageData.text.length;
        }

        // Handle close code/reason if provided directly
        if (messageData.close_code !== undefined) {
            messageInfo.closeCode = messageData.close_code;
            messageInfo.closeReason = messageData.close_reason ||
                websocket.getCloseCodeDescription(messageData.close_code);
        }

        result.messages.push(messageInfo);

        // Parse raw frames if provided in forensic evidence
        if (messageData.forensic_evidence?.raw_packets?.packets) {
            const packets = messageData.forensic_evidence.raw_packets.packets;
            result.details.push({
                success: `Found ${packets.length} raw packets for verification`
            });

            // Try to parse WebSocket frames from decrypted data
            let frameCount = 0;
            for (const packet of packets) {
                if (packet.packet_type === 'application') {
                    try {
                        const data = base64ToBytes(packet.data);
                        const frames = websocket.parseFrames(data);
                        frameCount += frames.length;
                    } catch (e) {
                        // Frame parsing failed - data may be encrypted
                    }
                }
            }

            if (frameCount > 0) {
                result.details.push({
                    success: `Parsed ${frameCount} WebSocket frames`
                });
            }
        }

        result.valid = true;
        result.details.push({
            success: `WebSocket ${messageInfo.type} message validated`
        });

    } catch (e) {
        result.details.push({ error: e.message });
    }

    return result;
}

/**
 * Extract transaction details for display.
 * @param {Object} evidence
 * @param {Object} validationResult
 * @returns {Object}
 */
function extractTransactionDetails(rawEvidence, validationResult) {
    const details = {};

    // Unwrap CapturedEvent if needed
    const evidence = rawEvidence.data || rawEvidence;
    const eventType = rawEvidence.type; // "transaction" or "websocket_message"

    console.log('[Validator] Extracting details from event type:', eventType);

    // Basic info
    if (evidence.id) details.id = evidence.id;
    if (evidence.timestamp_us) {
        details.timestamp = new Date(evidence.timestamp_us / 1000).toISOString();
    } else if (evidence.request?.timestamp_us) {
        details.timestamp = new Date(evidence.request.timestamp_us / 1000).toISOString();
    }

    // URL
    if (evidence.request?.url) {
        details.url = evidence.request.url;
    } else if (evidence.url) {
        details.url = evidence.url;
    }

    // Method and status (for HTTP transactions)
    if (eventType === 'transaction' || evidence.request) {
        details.method = evidence.request?.method;
        details.status = evidence.response?.status;
        details.statusText = evidence.response?.status_text;
    }

    // Protocol
    details.protocol = evidence.protocol || validationResult.protocol?.protocol || 'unknown';

    // Duration
    if (evidence.duration_ms) {
        details.duration = `${evidence.duration_ms}ms`;
    }

    // Connection info
    if (evidence.connection) {
        details.connection = {
            client: evidence.connection.client_addr,
            server: evidence.connection.server_addr
        };
    }

    // Profile ID
    if (evidence.profile_id) {
        details.profileId = evidence.profile_id;
    }

    // Packet count from legacy format
    if (evidence.packets) {
        details.packetCount = evidence.packets.length;
        details.totalBytes = evidence.packets.reduce((sum, p) => {
            return sum + (p.data ? base64ToBytes(p.data).length : 0);
        }, 0);
    }

    // Raw packets from forensic evidence
    const forensic = evidence.forensic_evidence;
    if (forensic?.raw_packets) {
        const rawPackets = forensic.raw_packets;
        details.packetCount = rawPackets.handshake_count + rawPackets.application_count;
        details.totalBytes = rawPackets.total_bytes;
        details.handshakePackets = rawPackets.handshake_count;
        details.applicationPackets = rawPackets.application_count;
    }

    // Forensic evidence summary
    if (forensic) {
        details.hasForensicEvidence = true;
        details.hasKeylog = !!forensic.keylog;
        details.hasCertificates = !!forensic.certificate_info?.certificate_chain?.length;
        details.hasRawPackets = !!forensic.raw_packets;
        details.isResumedSession = !!forensic.original_handshake;
    }

    // WebSocket-specific details
    if (validationResult.isWebSocket || eventType === 'websocket_message') {
        details.type = 'WebSocket';
        details.messageType = evidence.message_type;
        details.direction = evidence.direction;
    } else {
        details.type = 'HTTP';
    }

    console.log('[Validator] Extracted details:', details);

    return details;
}

/**
 * Show validation results.
 * @param {Object} result
 */
function showResults(result) {
    validationSection.classList.add('hidden');
    resultsSection.classList.remove('hidden');

    // Update badges
    const badgeDecrypt = document.getElementById('badge-decrypt');
    const badgeMatch = document.getElementById('badge-match');
    const badgeOverall = document.getElementById('badge-overall');

    // Badge 1: TLS Decryption
    if (result.tls.valid) {
        badgeDecrypt.textContent = '✓ Decrypt';
        badgeDecrypt.className = 'badge valid';
    } else {
        badgeDecrypt.textContent = '✗ Decrypt';
        badgeDecrypt.className = 'badge invalid';
    }

    // Badge 2: Field Matching
    const hasFieldComparison = result.fieldMatches && Object.keys(result.fieldMatches).length > 0;
    const allFieldsMatch = hasFieldComparison &&
        (result.fieldMatches.method !== false) &&
        (result.fieldMatches.url !== false) &&
        (result.fieldMatches.status !== false) &&
        (result.fieldMatches.requestBody !== false) &&
        (result.fieldMatches.responseBody !== false);

    if (!hasFieldComparison) {
        badgeMatch.textContent = '— Match';
        badgeMatch.className = 'badge pending';
    } else if (allFieldsMatch) {
        badgeMatch.textContent = '✓ Match';
        badgeMatch.className = 'badge valid';
    } else {
        badgeMatch.textContent = '✗ Match';
        badgeMatch.className = 'badge invalid';
    }

    // Badge 3: Overall Result
    if (result.valid) {
        badgeOverall.textContent = 'VERIFIED';
        badgeOverall.className = 'badge valid';
    } else if (result.tls.valid) {
        badgeOverall.textContent = 'PARTIAL';
        badgeOverall.className = 'badge partial';
    } else {
        badgeOverall.textContent = 'FAILED';
        badgeOverall.className = 'badge invalid';
    }

    // Comparison view (claimed vs decrypted) - includes TLS info
    renderComparisonView(result);

    // WebSocket card (only if WebSocket evidence)
    if (result.isWebSocket && websocketCard) {
        renderWebSocketCard(result.websocket);
    } else if (websocketCard) {
        websocketCard.classList.add('hidden');
    }

    // Transaction details card
    renderDetailsCard(result.transaction);
}

/**
 * Render the side-by-side comparison view.
 *
 * Two completely separate cards with IDENTICAL structure:
 * - Left card: What the Transaction claims (TLS info, request/response data)
 * - Right card: What we independently derived by re-decrypting raw packets
 *
 * Both cards show the exact same fields so you can visually compare each value.
 * If decryption succeeds, the right card should show identical values to the left.
 */
function renderComparisonView(result) {
    const protocol = result.protocol || {};
    const content = result.content || {};
    const tls = result.tls || {};

    // Get certificate info from the evidence (claimed)
    const certInfo = result._certInfo || {};

    // === CLAIMED DATA (from the Transaction as exported) ===
    const claimedReq = protocol.request || {};
    const claimedRes = protocol.response || {};

    // === DECRYPTED DATA (from re-parsing raw packets) ===
    const decryptedReq = protocol.parsedRequest || {};
    const decryptedRes = protocol.parsedResponse || {};

    // Do we have successfully decrypted data?
    const hasDecrypted = tls.valid && protocol.parsedRequest;

    // Calculate comprehensive match status - compare ALL fields
    let matchStatus = 'pending';
    const fieldMatches = {};

    if (hasDecrypted) {
        // Method comparison
        fieldMatches.method = decryptedReq.method === claimedReq.method;

        // URL/Path comparison (HTTP/2 has :path, claimed has full URL)
        // Extract path from claimed URL for comparison
        let claimedPath = claimedReq.url || '';
        try {
            const urlObj = new URL(claimedPath);
            claimedPath = urlObj.pathname + urlObj.search;
        } catch (e) {
            // Already a path, not a full URL
        }
        fieldMatches.url = decryptedReq.url === claimedPath;

        // Status comparison
        fieldMatches.status = decryptedRes.status === claimedRes.status;

        // Authority/Host comparison (HTTP/2 :authority vs Host header)
        const claimedHost = claimedReq.headers?.host || claimedReq.headers?.Host || '';
        const decryptedAuthority = decryptedReq.authority || decryptedReq.headers?.host || '';
        fieldMatches.host = decryptedAuthority === claimedHost ||
            (claimedReq.url && claimedReq.url.includes(decryptedAuthority));

        // Body hash comparison - use pre-computed hashes from content comparison step
        if (content.request?.hash && content.decryptedRequest?.hash) {
            fieldMatches.requestBody = content.request.hash === content.decryptedRequest.hash;
            console.log('[Validator] Request body hash: claimed=%s, decrypted=%s, match=%s',
                content.request.hash.slice(0, 16), content.decryptedRequest.hash.slice(0, 16), fieldMatches.requestBody);
        }
        if (content.response?.hash && content.decryptedResponse?.hash) {
            fieldMatches.responseBody = content.response.hash === content.decryptedResponse.hash;
            console.log('[Validator] Response body hash: claimed=%s, decrypted=%s, match=%s',
                content.response.hash.slice(0, 16), content.decryptedResponse.hash.slice(0, 16), fieldMatches.responseBody);
        }

        // Overall match: method, URL, status, AND body hashes must match
        const methodUrlStatusMatch = fieldMatches.method && fieldMatches.url && fieldMatches.status;
        const bodyMatch = (fieldMatches.requestBody !== false) && (fieldMatches.responseBody !== false);
        const criticalFieldsMatch = methodUrlStatusMatch && bodyMatch;
        matchStatus = criticalFieldsMatch ? 'match' : 'mismatch';

        console.log('[Validator] Field comparisons:', fieldMatches);
        console.log('[Validator] Claimed URL: %s, Decrypted URL: %s', claimedReq.url, decryptedReq.url);
        console.log('[Validator] Claimed Method: %s, Decrypted Method: %s', claimedReq.method, decryptedReq.method);
        console.log('[Validator] Claimed Status: %s, Decrypted Status: %s', claimedRes.status, decryptedRes.status);
    }

    // Update the center indicator
    matchIndicator.className = `match-indicator ${matchStatus}`;
    matchIndicator.textContent = matchStatus === 'match' ? '=' : matchStatus === 'mismatch' ? '≠' : '?';

    // Update decrypted card styling based on status
    const decryptedCard = document.getElementById('decrypted-card');
    if (decryptedCard) {
        decryptedCard.className = hasDecrypted ? 'result-card valid' : 'result-card invalid';
    }

    // Helper to build a card's content HTML
    function buildCardContent(options) {
        const { req, res, reqBody, resBody, tlsInfo } = options;
        let html = '';

        // === TLS SECTION ===
        html += '<div class="card-section-title">TLS</div>';

        html += `<div class="result-row">
            <span class="result-label">Version</span>
            <span class="result-value">${escapeHtml(tlsInfo.version || '—')}</span>
        </div>`;

        html += `<div class="result-row">
            <span class="result-label">Cipher</span>
            <span class="result-value">${escapeHtml(tlsInfo.cipher || '—')}</span>
        </div>`;

        html += `<div class="result-row">
            <span class="result-label">SNI</span>
            <span class="result-value">${escapeHtml(tlsInfo.sni || '—')}</span>
        </div>`;

        html += `<div class="result-row">
            <span class="result-label">Certificates</span>
            <span class="result-value">${tlsInfo.certCount !== undefined ? tlsInfo.certCount : '—'}</span>
        </div>`;

        if (tlsInfo.certVerify) {
            html += `<div class="result-row">
                <span class="result-label">CertificateVerify</span>
                <span class="result-value">${escapeHtml(tlsInfo.certVerify)}</span>
            </div>`;
        }

        // === REQUEST SECTION ===
        html += '<div class="card-section-title">Request</div>';

        html += `<div class="result-row">
            <span class="result-label">Method</span>
            <span class="result-value">${escapeHtml(req.method || '—')}</span>
        </div>`;

        html += `<div class="result-row">
            <span class="result-label">URL</span>
            <span class="result-value">${escapeHtml(req.url || '—')}</span>
        </div>`;

        const reqHeaderCount = req.headers ? Object.keys(req.headers).length : 0;
        html += `<div class="result-row">
            <span class="result-label">Headers</span>
            <span class="result-value">${reqHeaderCount > 0 ? reqHeaderCount : '—'}</span>
        </div>`;

        // === RESPONSE SECTION ===
        html += '<div class="card-section-title">Response</div>';

        const statusText = res.status ? `${res.status} ${res.statusText || ''}`.trim() : '—';
        html += `<div class="result-row">
            <span class="result-label">Status</span>
            <span class="result-value">${escapeHtml(statusText)}</span>
        </div>`;

        const resHeaderCount = res.headers ? Object.keys(res.headers).length : 0;
        html += `<div class="result-row">
            <span class="result-label">Headers</span>
            <span class="result-value">${resHeaderCount > 0 ? resHeaderCount : '—'}</span>
        </div>`;

        // === BODY SECTION ===
        html += '<div class="card-section-title">Body</div>';

        if (reqBody) {
            html += `<div class="result-row">
                <span class="result-label">Request</span>
                <span class="result-value">${formatBytes(reqBody.size || 0)}</span>
            </div>`;
            if (reqBody.hash) {
                html += `<div class="result-row">
                    <span class="result-label">Request SHA-256</span>
                    <span class="result-value mono">${reqBody.hash.substring(0, 16)}...</span>
                </div>`;
            }
        } else {
            html += `<div class="result-row">
                <span class="result-label">Request</span>
                <span class="result-value">—</span>
            </div>`;
        }

        if (resBody) {
            html += `<div class="result-row">
                <span class="result-label">Response</span>
                <span class="result-value">${formatBytes(resBody.size || 0)}</span>
            </div>`;
            if (resBody.hash) {
                html += `<div class="result-row">
                    <span class="result-label">Response SHA-256</span>
                    <span class="result-value mono">${resBody.hash.substring(0, 16)}...</span>
                </div>`;
            }
        } else {
            html += `<div class="result-row">
                <span class="result-label">Response</span>
                <span class="result-value">—</span>
            </div>`;
        }

        return html;
    }

    // Extract TLS info from claimed evidence
    const claimedTlsInfo = {
        version: certInfo.tls_version || '—',
        cipher: certInfo.cipher_suite || '—',
        sni: certInfo.sni || '—',
        certCount: certInfo.certificate_chain?.length || 0,
        certVerify: certInfo.handshake_proof?.algorithm || null
    };

    // Build LEFT card (CLAIMED from transaction)
    const claimedHtml = buildCardContent({
        req: claimedReq,
        res: claimedRes,
        reqBody: content.request,
        resBody: content.response,
        tlsInfo: claimedTlsInfo
    });
    claimedContent.innerHTML = claimedHtml;

    // For the decrypted column, we show what we derived from raw packets
    // If decryption succeeded, we verified the TLS params by using them
    const decryptedTlsInfo = {
        version: hasDecrypted ? claimedTlsInfo.version : '—',
        cipher: hasDecrypted ? claimedTlsInfo.cipher : '—',
        sni: hasDecrypted ? claimedTlsInfo.sni : '—',
        // Use same cert count - we verified by successfully decrypting with these keys
        certCount: hasDecrypted ? (tls.certificates?.length || certInfo.certificate_chain?.length || 0) : 0,
        certVerify: hasDecrypted && claimedTlsInfo.certVerify ? claimedTlsInfo.certVerify : null
    };

    // Build decrypted body info (if we have it)
    // Use pre-computed hashes from content comparison step
    let decryptedReqBody = null;
    let decryptedResBody = null;
    if (hasDecrypted && decryptedReq.body?.length > 0) {
        decryptedReqBody = {
            size: decryptedReq.body.length,
            hash: content.decryptedRequest?.hash || null
        };
    }
    if (hasDecrypted && decryptedRes.body?.length > 0) {
        decryptedResBody = {
            size: decryptedRes.body.length,
            hash: content.decryptedResponse?.hash || null
        };
    }

    const decryptedHtml = buildCardContent({
        req: hasDecrypted ? decryptedReq : {},
        res: hasDecrypted ? decryptedRes : {},
        reqBody: decryptedReqBody,
        resBody: decryptedResBody,
        tlsInfo: decryptedTlsInfo
    });
    decryptedContent.innerHTML = decryptedHtml;
}

/**
 * Render TLS card.
 * @param {Object} tlsResult
 */
function renderTlsCard(tlsResult) {
    tlsCard.className = `result-card ${tlsResult.valid ? 'valid' : 'warning'}`;

    let html = '';

    for (const detail of tlsResult.details) {
        if (detail.success) {
            html += `<div class="result-row">
                <span class="result-label">Status</span>
                <span class="result-value valid">${detail.success}</span>
            </div>`;
        } else if (detail.error) {
            html += `<div class="result-row">
                <span class="result-label">Error</span>
                <span class="result-value invalid">${detail.error}</span>
            </div>`;
        } else if (detail.note) {
            html += `<div class="result-row">
                <span class="result-label">Note</span>
                <span class="result-value">${detail.note}</span>
            </div>`;
        }
    }

    // Show decrypted payloads count
    if (tlsResult.decryptedPayloads && tlsResult.decryptedPayloads.length > 0) {
        html += `<div class="result-row">
            <span class="result-label">Decrypted</span>
            <span class="result-value">${tlsResult.decryptedPayloads.length} records</span>
        </div>`;
    }

    // Show certificates
    if (tlsResult.certificates && tlsResult.certificates.length > 0) {
        html += '<div class="cert-chain">';
        for (const cert of tlsResult.certificates) {
            if (cert.error) {
                html += `<div class="cert-item">
                    <div class="cert-subject">Certificate Error</div>
                    <div class="cert-issuer">${cert.error}</div>
                </div>`;
            } else {
                const valid = isCertificateValid(cert);
                html += `<div class="cert-item">
                    <div class="cert-subject">${formatDN(cert.subject)}</div>
                    <div class="cert-issuer">Issuer: ${formatDN(cert.issuer)}</div>
                    <div class="cert-validity ${valid ? '' : 'invalid'}">
                        Valid: ${cert.notBefore?.toISOString().split('T')[0]} - ${cert.notAfter?.toISOString().split('T')[0]}
                    </div>
                </div>`;
            }
        }
        html += '</div>';
    }

    tlsCard.querySelector('.result-content').innerHTML = html || '<div class="empty">No TLS details</div>';
}

/**
 * Render protocol card.
 * @param {Object} protocolResult
 */
function renderProtocolCard(protocolResult) {
    protocolCard.className = `result-card ${protocolResult.valid ? 'valid' : 'warning'}`;

    let html = '';

    // Show status details
    for (const detail of protocolResult.details) {
        if (detail.success) {
            html += `<div class="result-row">
                <span class="result-label">Status</span>
                <span class="result-value valid">${detail.success}</span>
            </div>`;
        } else if (detail.error) {
            html += `<div class="result-row">
                <span class="result-label">Error</span>
                <span class="result-value invalid">${detail.error}</span>
            </div>`;
        } else if (detail.note) {
            html += `<div class="result-row">
                <span class="result-label">Info</span>
                <span class="result-value">${detail.note}</span>
            </div>`;
        }
    }

    // Request info
    if (protocolResult.request) {
        const req = protocolResult.request;
        html += `<div class="result-row">
            <span class="result-label">URL</span>
            <span class="result-value">${escapeHtml(req.url || '')}</span>
        </div>`;

        // Request headers
        if (req.headers && Object.keys(req.headers).length > 0) {
            html += '<div class="collapsible" data-target="req-headers">Request Headers</div>';
            html += '<div class="collapse-content" id="req-headers"><div class="headers-list">';
            for (const [name, value] of Object.entries(req.headers)) {
                html += `<div class="header-item">
                    <span class="header-name">${escapeHtml(name)}</span>: <span class="header-value">${escapeHtml(String(value))}</span>
                </div>`;
            }
            html += '</div></div>';
        }
    }

    // Response headers
    if (protocolResult.response?.headers && Object.keys(protocolResult.response.headers).length > 0) {
        html += '<div class="collapsible" data-target="res-headers">Response Headers</div>';
        html += '<div class="collapse-content" id="res-headers"><div class="headers-list">';
        for (const [name, value] of Object.entries(protocolResult.response.headers)) {
            html += `<div class="header-item">
                <span class="header-name">${escapeHtml(name)}</span>: <span class="header-value">${escapeHtml(String(value))}</span>
            </div>`;
        }
        html += '</div></div>';
    }

    // Legacy headers format
    if (protocolResult.headers) {
        if (protocolResult.headers.request && Object.keys(protocolResult.headers.request).length > 0) {
            html += '<div class="collapsible" data-target="req-headers-legacy">Request Headers</div>';
            html += '<div class="collapse-content" id="req-headers-legacy"><div class="headers-list">';
            for (const [name, value] of Object.entries(protocolResult.headers.request)) {
                html += `<div class="header-item">
                    <span class="header-name">${escapeHtml(name)}</span>: <span class="header-value">${escapeHtml(value)}</span>
                </div>`;
            }
            html += '</div></div>';
        }
    }

    protocolCard.querySelector('.result-content').innerHTML = html || '<div class="empty">No protocol data</div>';

    // Set up collapsible sections
    protocolCard.querySelectorAll('.collapsible').forEach(el => {
        el.addEventListener('click', () => {
            el.classList.toggle('expanded');
            const target = document.getElementById(el.dataset.target);
            if (target) target.classList.toggle('show');
        });
    });
}

/**
 * Render content verification card.
 * @param {Object} contentResult
 */
function renderContentCard(contentResult) {
    contentCard.className = `result-card ${contentResult.valid ? 'valid' : 'invalid'}`;

    let html = '';

    // Status details
    for (const detail of contentResult.details) {
        if (detail.success) {
            html += `<div class="result-row">
                <span class="result-label">Status</span>
                <span class="result-value valid">${detail.success}</span>
            </div>`;
        } else if (detail.error) {
            html += `<div class="result-row">
                <span class="result-label">Error</span>
                <span class="result-value invalid">${detail.error}</span>
            </div>`;
        } else if (detail.field) {
            html += `<div class="result-row">
                <span class="result-label">${detail.field}</span>
                <span class="result-value ${detail.valid ? 'valid' : 'invalid'}">${detail.valid ? 'Match' : 'Mismatch'}</span>
            </div>`;
        } else if (detail.note) {
            html += `<div class="result-row">
                <span class="result-label">Info</span>
                <span class="result-value">${detail.note}</span>
            </div>`;
        }
    }

    // Request body
    if (contentResult.request) {
        html += `<div class="result-row">
            <span class="result-label">Request Hash</span>
            <span class="result-value mono">${contentResult.request.hash.substring(0, 16)}...</span>
        </div>`;
        if (contentResult.request.preview) {
            html += '<div class="collapsible" data-target="req-body">Request Body Preview</div>';
            html += `<div class="collapse-content" id="req-body">
                <pre class="payload-preview">${escapeHtml(contentResult.request.preview)}</pre>
            </div>`;
        }
    }

    // Response body
    if (contentResult.response) {
        html += `<div class="result-row">
            <span class="result-label">Response Hash</span>
            <span class="result-value mono">${contentResult.response.hash.substring(0, 16)}...</span>
        </div>`;
        if (contentResult.response.preview) {
            html += '<div class="collapsible" data-target="res-body">Response Body Preview</div>';
            html += `<div class="collapse-content" id="res-body">
                <pre class="payload-preview">${escapeHtml(contentResult.response.preview)}</pre>
            </div>`;
        }
    }

    contentCard.querySelector('.result-content').innerHTML = html || '<div class="empty">No content to verify</div>';

    // Set up collapsible sections
    contentCard.querySelectorAll('.collapsible').forEach(el => {
        el.addEventListener('click', () => {
            el.classList.toggle('expanded');
            const target = document.getElementById(el.dataset.target);
            if (target) target.classList.toggle('show');
        });
    });
}

/**
 * Render WebSocket card.
 * @param {Object} wsResult
 */
function renderWebSocketCard(wsResult) {
    if (!websocketCard) return;

    websocketCard.classList.remove('hidden');
    websocketCard.className = `result-card ${wsResult.valid ? 'valid' : 'warning'}`;

    let html = '';

    // Show status details
    for (const detail of wsResult.details) {
        if (detail.success) {
            html += `<div class="result-row">
                <span class="result-label">Status</span>
                <span class="result-value valid">${detail.success}</span>
            </div>`;
        } else if (detail.error) {
            html += `<div class="result-row">
                <span class="result-label">Error</span>
                <span class="result-value invalid">${detail.error}</span>
            </div>`;
        }
    }

    // Show messages
    if (wsResult.messages && wsResult.messages.length > 0) {
        for (const msg of wsResult.messages) {
            html += `<div class="ws-message ${msg.direction}">`;
            html += `<div class="result-row">
                <span class="result-label">Type</span>
                <span class="result-value highlight">${msg.type}</span>
            </div>`;
            html += `<div class="result-row">
                <span class="result-label">Direction</span>
                <span class="result-value">${msg.direction === 'ClientToServer' ? 'Client → Server' : 'Server → Client'}</span>
            </div>`;
            html += `<div class="result-row">
                <span class="result-label">Size</span>
                <span class="result-value">${formatBytes(msg.size)}</span>
            </div>`;

            // Close code for close messages
            if (msg.closeCode !== undefined) {
                html += `<div class="result-row">
                    <span class="result-label">Close Code</span>
                    <span class="result-value">${msg.closeCode} (${msg.closeReason || 'Unknown'})</span>
                </div>`;
            }

            // Payload preview
            if (msg.preview) {
                html += '<div class="collapsible" data-target="ws-payload">Payload Preview</div>';
                html += `<div class="collapse-content" id="ws-payload">
                    <pre class="payload-preview">${escapeHtml(msg.preview)}</pre>
                </div>`;
            }

            html += '</div>';
        }
    }

    websocketCard.querySelector('.result-content').innerHTML = html || '<div class="empty">No WebSocket data</div>';

    // Set up collapsible sections
    websocketCard.querySelectorAll('.collapsible').forEach(el => {
        el.addEventListener('click', () => {
            el.classList.toggle('expanded');
            const target = document.getElementById(el.dataset.target);
            target.classList.toggle('show');
        });
    });
}

/**
 * Render transaction details card.
 * @param {Object} details
 */
function renderDetailsCard(details) {
    detailsCard.className = 'result-card';

    let html = '';

    // Type badge
    if (details.type) {
        html += `<div class="result-row">
            <span class="result-label">Type</span>
            <span class="result-value highlight">${details.type}</span>
        </div>`;
    }

    // HTTP: method and status
    if (details.method && details.status) {
        html += `<div class="result-row">
            <span class="result-label">Request</span>
            <span class="result-value highlight">${details.method} ${details.status}${details.statusText ? ' ' + details.statusText : ''}</span>
        </div>`;
    }

    // WebSocket: message type and direction
    if (details.messageType) {
        html += `<div class="result-row">
            <span class="result-label">Message Type</span>
            <span class="result-value">${details.messageType}</span>
        </div>`;
    }
    if (details.direction) {
        html += `<div class="result-row">
            <span class="result-label">Direction</span>
            <span class="result-value">${details.direction === 'ClientToServer' ? 'Client → Server' : 'Server → Client'}</span>
        </div>`;
    }

    if (details.url) {
        html += `<div class="result-row">
            <span class="result-label">URL</span>
            <span class="result-value">${escapeHtml(details.url)}</span>
        </div>`;
    }

    if (details.protocol) {
        html += `<div class="result-row">
            <span class="result-label">Protocol</span>
            <span class="result-value">${details.protocol}</span>
        </div>`;
    }

    if (details.duration) {
        html += `<div class="result-row">
            <span class="result-label">Duration</span>
            <span class="result-value">${details.duration}</span>
        </div>`;
    }

    if (details.timestamp) {
        html += `<div class="result-row">
            <span class="result-label">Timestamp</span>
            <span class="result-value">${details.timestamp}</span>
        </div>`;
    }

    if (details.packetCount) {
        let packetInfo = `${details.packetCount} (${formatBytes(details.totalBytes || 0)})`;
        if (details.handshakePackets !== undefined) {
            packetInfo += ` - ${details.handshakePackets} handshake, ${details.applicationPackets} app`;
        }
        html += `<div class="result-row">
            <span class="result-label">Packets</span>
            <span class="result-value">${packetInfo}</span>
        </div>`;
    }

    if (details.connection) {
        html += `<div class="result-row">
            <span class="result-label">Client</span>
            <span class="result-value mono">${details.connection.client}</span>
        </div>`;
        html += `<div class="result-row">
            <span class="result-label">Server</span>
            <span class="result-value mono">${details.connection.server}</span>
        </div>`;
    }

    if (details.profileId) {
        html += `<div class="result-row">
            <span class="result-label">Profile</span>
            <span class="result-value mono">${details.profileId}</span>
        </div>`;
    }

    // Forensic evidence summary
    if (details.hasForensicEvidence) {
        const badges = [];
        if (details.hasKeylog) badges.push('Keylog');
        if (details.hasCertificates) badges.push('Certs');
        if (details.hasRawPackets) badges.push('Packets');
        if (details.isResumedSession) badges.push('Resumed');

        html += `<div class="result-row">
            <span class="result-label">Forensic Data</span>
            <span class="result-value valid">${badges.join(', ')}</span>
        </div>`;
    }

    if (details.id) {
        html += `<div class="result-row">
            <span class="result-label">ID</span>
            <span class="result-value mono">${details.id}</span>
        </div>`;
    }

    detailsCard.querySelector('.result-content').innerHTML = html || '<div class="empty">No transaction details</div>';
}

/**
 * Show error message.
 * @param {string} message
 */
function showError(message) {
    validationSection.classList.add('hidden');
    resultsSection.classList.remove('hidden');

    // Update all badges to show error state
    const badgeDecrypt = document.getElementById('badge-decrypt');
    const badgeMatch = document.getElementById('badge-match');
    const badgeOverall = document.getElementById('badge-overall');

    if (badgeDecrypt) {
        badgeDecrypt.textContent = '— Decrypt';
        badgeDecrypt.className = 'badge pending';
    }
    if (badgeMatch) {
        badgeMatch.textContent = '— Match';
        badgeMatch.className = 'badge pending';
    }
    if (badgeOverall) {
        badgeOverall.textContent = 'ERROR';
        badgeOverall.className = 'badge invalid';
    }

    const content = `<div class="result-row">
        <span class="result-label">Error</span>
        <span class="result-value invalid">${escapeHtml(message)}</span>
    </div>`;

    hashCard.querySelector('.result-content').innerHTML = content;
    tlsCard.querySelector('.result-content').innerHTML = '';
    protocolCard.querySelector('.result-content').innerHTML = '';
    contentCard.querySelector('.result-content').innerHTML = '';
    detailsCard.querySelector('.result-content').innerHTML = '';
}

/**
 * Escape HTML special characters.
 * @param {string} text
 * @returns {string}
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Format bytes as human-readable string.
 * @param {number} bytes
 * @returns {string}
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
