import { createReadStream } from "fs";
import { createInterface } from "readline";
import { HpackDecoder } from "./js/protocol/hpack.js";

const rl = createInterface({
    input: createReadStream("/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl"),
    crlfDelay: Infinity
});

let count = 0;
for await (const line of rl) {
    if (!line.trim()) continue;
    const wrapper = JSON.parse(line);
    const tx = wrapper.data;
    if (tx.protocol === "HTTP/2") {
        count++;
        if (count === 1) {
            console.log("Testing first HTTP/2 transaction:", tx.id);
            console.log("Stream ID:", tx.forensic_evidence.h2_stream_id);
            console.log("HPACK request entries:", tx.forensic_evidence.hpack_request_table?.entries?.length);
            console.log("HPACK response entries:", tx.forensic_evidence.hpack_response_table?.entries?.length);

            try {
                const requestHpack = new HpackDecoder(tx.forensic_evidence.hpack_request_table);
                console.log("Request HPACK decoder created successfully");
            } catch (e) {
                console.log("Request HPACK decoder error:", e.message);
            }

            try {
                const responseHpack = new HpackDecoder(tx.forensic_evidence.hpack_response_table);
                console.log("Response HPACK decoder created successfully");
            } catch (e) {
                console.log("Response HPACK decoder error:", e.message);
            }
            break;
        }
    }
}
