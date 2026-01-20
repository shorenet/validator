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

// DOM elements
let dropZone, fileInput, pasteInput, validatePasteBtn;
let uploadSection, validationSection, resultsSection;
let progressBar, statusText;
let resultsBadge, hashCard, tlsCard, protocolCard, contentCard, detailsCard, websocketCard;

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
    resultsBadge = document.getElementById('results-badge');
    hashCard = document.getElementById('hash-verification');
    tlsCard = document.getElementById('tls-decryption');
    protocolCard = document.getElementById('protocol-parsing');
    contentCard = document.getElementById('content-verification');
    detailsCard = document.getElementById('transaction-details');
    websocketCard = document.getElementById('websocket-messages');
    pasteInput = document.getElementById('paste-input');
    validatePasteBtn = document.getElementById('validate-paste-btn');

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

        const evidence = JSON.parse(text);

        updateProgress(20, 'Validating structure...');

        // Validate evidence structure
        const validationResult = await validateEvidence(evidence);

        // Show results
        showResults(validationResult);

    } catch (error) {
        console.error('Validation error:', error);
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
 * Validate forensic evidence.
 * @param {Object} evidence
 * @returns {Promise<Object>}
 */
async function validateEvidence(evidence) {
    const result = {
        valid: true,
        hash: { valid: false, details: [] },
        tls: { valid: false, details: [], certificates: [] },
        protocol: { valid: false, details: [], headers: null },
        content: { valid: false, details: [] },
        websocket: { valid: false, details: [], messages: [] },
        transaction: {},
        isWebSocket: false
    };

    // Detect if this is WebSocket evidence
    result.isWebSocket = isWebSocketEvidence(evidence);

    try {
        // 1. Verify hash chain
        updateProgress(30, 'Verifying hash chain...');
        if (evidence.packets && evidence.packets.length > 0) {
            const hashResult = await verifyHashChain(evidence.packets);
            result.hash.valid = hashResult.valid;
            result.hash.details = hashResult.details;
            result.hash.finalHash = hashResult.finalHash;
        } else {
            result.hash.details.push({ error: 'No packets in evidence' });
        }

        // 2. TLS decryption (if keys are provided)
        updateProgress(50, 'Decrypting TLS...');
        if (evidence.keylog && evidence.packets) {
            try {
                const tlsResult = await decryptTls(evidence);
                result.tls = tlsResult;
            } catch (e) {
                result.tls.details.push({ error: `TLS decryption failed: ${e.message}` });
            }
        } else {
            result.tls.details.push({ note: 'No keylog data - using provided plaintext' });
            result.tls.valid = true;
        }

        // 3. Protocol parsing
        updateProgress(70, 'Parsing protocol...');
        const protocolResult = await parseProtocol(evidence, result.tls);
        result.protocol = protocolResult;

        // 4. Content verification
        updateProgress(85, 'Verifying content...');
        if (evidence.request_body_hash || evidence.response_body_hash) {
            const contentResult = await verifyContent(evidence);
            result.content = contentResult;
        } else {
            result.content.valid = true;
            result.content.details.push({ note: 'No body hashes to verify' });
        }

        // 5. WebSocket messages (if present)
        if (result.isWebSocket) {
            updateProgress(90, 'Validating WebSocket messages...');
            result.websocket = await validateWebSocketMessages(evidence);
        }

        // 6. Extract transaction details
        updateProgress(95, 'Extracting details...');
        result.transaction = extractTransactionDetails(evidence, result);

        // Overall validity
        result.valid = result.hash.valid;

    } catch (error) {
        result.valid = false;
        result.error = error.message;
    }

    updateProgress(100, 'Complete');
    return result;
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
function extractTransactionDetails(evidence, validationResult) {
    const details = {};

    // Basic info
    if (evidence.id) details.id = evidence.id;
    if (evidence.timestamp_us) {
        details.timestamp = new Date(evidence.timestamp_us / 1000).toISOString();
    }

    // URL
    if (evidence.request?.url) {
        details.url = evidence.request.url;
    }

    // Method and status
    const headers = validationResult.protocol?.headers || {};
    if (headers.request?.[':method']) {
        details.method = headers.request[':method'];
    } else if (evidence.request?.method) {
        details.method = evidence.request.method;
    }

    if (headers.response?.[':status']) {
        details.status = headers.response[':status'];
    } else if (evidence.response?.status) {
        details.status = evidence.response.status;
    }

    // Protocol
    details.protocol = validationResult.protocol?.protocol || evidence.protocol || 'unknown';

    // Connection info
    if (evidence.connection) {
        details.connection = {
            client: evidence.connection.client_addr,
            server: evidence.connection.server_addr
        };
    }

    // Packet count
    if (evidence.packets) {
        details.packetCount = evidence.packets.length;
        details.totalBytes = evidence.packets.reduce((sum, p) => {
            return sum + (p.data ? base64ToBytes(p.data).length : 0);
        }, 0);
    }

    // Raw packets from forensic evidence
    if (evidence.forensic_evidence?.raw_packets) {
        const rawPackets = evidence.forensic_evidence.raw_packets;
        details.packetCount = rawPackets.handshake_count + rawPackets.application_count;
        details.totalBytes = rawPackets.total_bytes;
    }

    // WebSocket-specific details
    if (validationResult.isWebSocket) {
        const msgData = evidence.data || evidence;
        details.type = 'WebSocket';
        details.messageType = msgData.message_type;
        details.direction = msgData.direction;
        if (msgData.url) {
            details.url = msgData.url;
        }
    }

    return details;
}

/**
 * Show validation results.
 * @param {Object} result
 */
function showResults(result) {
    validationSection.classList.add('hidden');
    resultsSection.classList.remove('hidden');

    // Update badge
    if (result.valid) {
        resultsBadge.textContent = 'VALID';
        resultsBadge.className = 'badge valid';
    } else if (result.hash.valid) {
        resultsBadge.textContent = 'PARTIAL';
        resultsBadge.className = 'badge partial';
    } else {
        resultsBadge.textContent = 'INVALID';
        resultsBadge.className = 'badge invalid';
    }

    // Hash verification card
    renderHashCard(result.hash);

    // TLS card
    renderTlsCard(result.tls);

    // Protocol card
    renderProtocolCard(result.protocol);

    // Content card
    renderContentCard(result.content);

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
 * Render hash verification card.
 * @param {Object} hashResult
 */
function renderHashCard(hashResult) {
    hashCard.className = `result-card ${hashResult.valid ? 'valid' : 'invalid'}`;

    let html = '';

    if (hashResult.finalHash) {
        html += `<div class="result-row">
            <span class="result-label">Final Hash</span>
            <span class="result-value ${hashResult.valid ? 'valid' : 'invalid'}">${hashResult.finalHash.substring(0, 16)}...</span>
        </div>`;
    }

    html += `<div class="result-row">
        <span class="result-label">Packets Verified</span>
        <span class="result-value">${hashResult.details.length}</span>
    </div>`;

    // Show any failed hashes
    const failed = hashResult.details.filter(d => !d.valid);
    if (failed.length > 0) {
        html += `<div class="result-row">
            <span class="result-label">Failed</span>
            <span class="result-value invalid">${failed.length} packet(s)</span>
        </div>`;
    }

    hashCard.querySelector('.result-content').innerHTML = html;
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

    let html = `<div class="result-row">
        <span class="result-label">Protocol</span>
        <span class="result-value highlight">${protocolResult.protocol}</span>
    </div>`;

    if (protocolResult.headers) {
        // Request headers
        if (Object.keys(protocolResult.headers.request).length > 0) {
            html += '<div class="collapsible" data-target="req-headers">Request Headers</div>';
            html += '<div class="collapse-content" id="req-headers"><div class="headers-list">';
            for (const [name, value] of Object.entries(protocolResult.headers.request)) {
                html += `<div class="header-item">
                    <span class="header-name">${escapeHtml(name)}</span>: <span class="header-value">${escapeHtml(value)}</span>
                </div>`;
            }
            html += '</div></div>';
        }

        // Response headers
        if (Object.keys(protocolResult.headers.response).length > 0) {
            html += '<div class="collapsible" data-target="res-headers">Response Headers</div>';
            html += '<div class="collapse-content" id="res-headers"><div class="headers-list">';
            for (const [name, value] of Object.entries(protocolResult.headers.response)) {
                html += `<div class="header-item">
                    <span class="header-name">${escapeHtml(name)}</span>: <span class="header-value">${escapeHtml(value)}</span>
                </div>`;
            }
            html += '</div></div>';
        }
    }

    protocolCard.querySelector('.result-content').innerHTML = html;

    // Set up collapsible sections
    protocolCard.querySelectorAll('.collapsible').forEach(el => {
        el.addEventListener('click', () => {
            el.classList.toggle('expanded');
            const target = document.getElementById(el.dataset.target);
            target.classList.toggle('show');
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

    for (const detail of contentResult.details) {
        if (detail.field) {
            html += `<div class="result-row">
                <span class="result-label">${detail.field}</span>
                <span class="result-value ${detail.valid ? 'valid' : 'invalid'}">${detail.valid ? 'Match' : 'Mismatch'}</span>
            </div>`;
        } else if (detail.note) {
            html += `<div class="result-row">
                <span class="result-label">Note</span>
                <span class="result-value">${detail.note}</span>
            </div>`;
        }
    }

    contentCard.querySelector('.result-content').innerHTML = html || '<div class="empty">No content to verify</div>';
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

    if (details.method && details.status) {
        html += `<div class="result-row">
            <span class="result-label">Request</span>
            <span class="result-value highlight">${details.method} ${details.status}</span>
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

    if (details.timestamp) {
        html += `<div class="result-row">
            <span class="result-label">Timestamp</span>
            <span class="result-value">${details.timestamp}</span>
        </div>`;
    }

    if (details.packetCount) {
        html += `<div class="result-row">
            <span class="result-label">Packets</span>
            <span class="result-value">${details.packetCount} (${formatBytes(details.totalBytes)})</span>
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

    resultsBadge.textContent = 'ERROR';
    resultsBadge.className = 'badge invalid';

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
