/**
 * TCP Stream Reassembly per RFC 793
 *
 * Handles:
 * - Out-of-order packet delivery
 * - TCP sequence number wraparound (32-bit)
 * - Retransmission detection and handling
 * - Overlapping segments
 */

/**
 * TCP flags
 */
export const TCP_FLAGS = {
    FIN: 0x01,
    SYN: 0x02,
    RST: 0x04,
    PSH: 0x08,
    ACK: 0x10,
    URG: 0x20,
};

/**
 * Parse TCP header from raw packet data
 * @param {Uint8Array} data - Raw packet bytes (starting at TCP header)
 * @returns {Object|null} Parsed TCP header or null
 */
export function parseTcpHeader(data) {
    if (!data || data.length < 20) return null;

    const srcPort = (data[0] << 8) | data[1];
    const dstPort = (data[2] << 8) | data[3];
    const seqNum = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    const ackNum = (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];
    const dataOffset = (data[12] >> 4) * 4; // Header length in bytes
    const flags = data[13];

    if (dataOffset < 20 || dataOffset > data.length) return null;

    const payload = data.slice(dataOffset);

    return {
        srcPort,
        dstPort,
        seqNum: seqNum >>> 0, // Ensure unsigned 32-bit
        ackNum: ackNum >>> 0,
        dataOffset,
        flags,
        payload,
        isSyn: (flags & TCP_FLAGS.SYN) !== 0,
        isFin: (flags & TCP_FLAGS.FIN) !== 0,
        isAck: (flags & TCP_FLAGS.ACK) !== 0,
        isRst: (flags & TCP_FLAGS.RST) !== 0,
    };
}

/**
 * Extract TLS payload from raw packet data.
 *
 * Packets are now stored as TLS-only (TCP headers stripped at capture time).
 * This function simply returns the raw data as the payload.
 *
 * @param {Uint8Array} data - Raw packet bytes (TLS payload only)
 * @returns {Object|null} Segment info with payload, or null
 */
export function extractTcpSegment(data) {
    if (!data || data.length < 1) return null;

    // All packets are now TLS-only - return raw data as payload
    return {
        srcPort: 0,
        dstPort: 0,
        seqNum: 0,
        ackNum: 0,
        dataOffset: 0,
        flags: 0,
        payload: data,
        isSyn: false,
        isFin: false,
        isAck: false,
        isRst: false,
        isTlsOnly: true,
    };
}

/**
 * TCP sequence number comparison with wraparound handling.
 * Returns true if seq `a` is before seq `b` in sequence space.
 * Per RFC 793 Section 3.3, sequence numbers are compared modulo 2^32.
 *
 * @param {number} a - First sequence number
 * @param {number} b - Second sequence number
 * @returns {boolean} True if a is before b
 */
function seqBefore(a, b) {
    // Convert to signed 32-bit comparison
    // If (b - a) is positive and < 2^31, then a is before b
    const diff = (b - a) >>> 0;
    return diff > 0 && diff < 0x80000000;
}

/**
 * TCP stream reassembler per RFC 793.
 *
 * Processes TCP segments and produces an ordered byte stream,
 * handling retransmissions, out-of-order delivery, and overlapping segments.
 */
export class TcpStream {
    constructor() {
        /** @type {number|null} Initial sequence number from SYN */
        this.initialSeq = null;
        /** @type {number} Next expected sequence number */
        this.nextSeq = 0;
        /** @type {Map<number, Uint8Array>} Out-of-order segments (seq -> data) */
        this.pending = new Map();
        /** @type {number} Total bytes reassembled */
        this.bytesReassembled = 0;
        /** @type {number} Total bytes dropped (retransmits, overlaps) */
        this.bytesDropped = 0;
        /** @type {boolean} Whether FIN has been received */
        this.finished = false;

        // Limits
        this.maxGapSize = 1024 * 1024; // 1 MB
        this.maxPendingSegments = 1000;
    }

    /**
     * Set the initial sequence number from SYN packet.
     * @param {number} seq - ISN from SYN packet
     */
    setInitialSeq(seq) {
        this.initialSeq = seq >>> 0;
        // ISN + 1 is the first data byte (SYN consumes one sequence number)
        this.nextSeq = ((seq + 1) >>> 0);
    }

    /**
     * Process a TCP segment and return any reassembled data.
     * @param {number} seq - Sequence number of segment
     * @param {Uint8Array} data - Payload data
     * @returns {Uint8Array|null} Reassembled in-order data, if any
     */
    processSegment(seq, data) {
        if (!data || data.length === 0) return null;

        seq = seq >>> 0; // Ensure unsigned 32-bit

        // If we haven't seen SYN, use first data packet to initialize
        if (this.initialSeq === null) {
            this.initialSeq = ((seq - 1) >>> 0);
            this.nextSeq = seq;
        }

        // Check if this segment is what we're expecting
        if (seq === this.nextSeq) {
            return this._handleInOrderSegment(data);
        }

        // Check if segment is before our expected sequence (retransmit or overlap)
        if (seqBefore(seq, this.nextSeq)) {
            return this._handleOverlap(seq, data);
        }

        // Future segment - buffer it for later
        this._bufferOooSegment(seq, data);
        return null;
    }

    /**
     * Handle an in-order segment.
     * @private
     */
    _handleInOrderSegment(data) {
        const result = [data];
        this.nextSeq = ((this.nextSeq + data.length) >>> 0);
        this.bytesReassembled += data.length;

        // Check if we can now deliver any buffered segments
        const sortedSeqs = Array.from(this.pending.keys()).sort((a, b) => {
            // Sort by sequence number, handling wraparound
            if (seqBefore(a, b)) return -1;
            if (seqBefore(b, a)) return 1;
            return 0;
        });

        for (const pendingSeq of sortedSeqs) {
            if (pendingSeq === this.nextSeq) {
                const segment = this.pending.get(pendingSeq);
                this.pending.delete(pendingSeq);
                result.push(segment);
                this.nextSeq = ((this.nextSeq + segment.length) >>> 0);
                this.bytesReassembled += segment.length;
            } else if (seqBefore(pendingSeq, this.nextSeq)) {
                // Old segment, discard
                const segment = this.pending.get(pendingSeq);
                this.pending.delete(pendingSeq);
                this.bytesDropped += segment.length;
            } else {
                // Gap - stop here
                break;
            }
        }

        if (result.length === 0) return null;
        if (result.length === 1) return result[0];

        // Concatenate all segments
        const totalLen = result.reduce((sum, arr) => sum + arr.length, 0);
        const combined = new Uint8Array(totalLen);
        let offset = 0;
        for (const segment of result) {
            combined.set(segment, offset);
            offset += segment.length;
        }
        return combined;
    }

    /**
     * Handle an overlapping segment (retransmit or partial overlap).
     * Per RFC 793 Section 3.9, overlapping segments are handled by
     * discarding already-received data and keeping only new data.
     * @private
     */
    _handleOverlap(seq, data) {
        // Calculate how much of this segment is old data
        const overlap = ((this.nextSeq - seq) >>> 0);

        if (overlap >= data.length) {
            // Entire segment is old data (retransmit)
            this.bytesDropped += data.length;
            return null;
        }

        // Partial overlap - extract only the new data
        const newData = data.slice(overlap);
        return this._handleInOrderSegment(newData);
    }

    /**
     * Buffer an out-of-order segment for later processing.
     * @private
     */
    _bufferOooSegment(seq, data) {
        // Check gap size
        const gap = ((seq - this.nextSeq) >>> 0);
        if (gap > this.maxGapSize) {
            this.bytesDropped += data.length;
            return;
        }

        // Check segment count limit
        if (this.pending.size >= this.maxPendingSegments) {
            // Drop oldest pending segment
            const sortedSeqs = Array.from(this.pending.keys()).sort((a, b) => {
                if (seqBefore(a, b)) return -1;
                if (seqBefore(b, a)) return 1;
                return 0;
            });
            if (sortedSeqs.length > 0) {
                const oldest = sortedSeqs[0];
                const dropped = this.pending.get(oldest);
                this.pending.delete(oldest);
                this.bytesDropped += dropped.length;
            }
        }

        this.pending.set(seq, data);
    }

    /**
     * Mark stream as finished (FIN received).
     */
    finish() {
        this.finished = true;
    }

    /**
     * Get reassembly statistics.
     */
    getStats() {
        return {
            bytesReassembled: this.bytesReassembled,
            bytesDropped: this.bytesDropped,
            pendingSegments: this.pending.size,
            finished: this.finished,
        };
    }
}

/**
 * Reassemble TCP stream from packets.
 * This is the main entry point for TCP reassembly.
 *
 * @param {Array<{seq: number, data: Uint8Array}>} segments - TCP segments with sequence numbers
 * @returns {Uint8Array} Reassembled stream
 */
export function reassembleTcpStream(segments) {
    const stream = new TcpStream();
    const results = [];

    for (const { seq, data } of segments) {
        const reassembled = stream.processSegment(seq, data);
        if (reassembled) {
            results.push(reassembled);
        }
    }

    if (results.length === 0) return new Uint8Array(0);
    if (results.length === 1) return results[0];

    const totalLen = results.reduce((sum, arr) => sum + arr.length, 0);
    const combined = new Uint8Array(totalLen);
    let offset = 0;
    for (const segment of results) {
        combined.set(segment, offset);
        offset += segment.length;
    }
    return combined;
}
