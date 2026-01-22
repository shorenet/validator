#!/usr/bin/env python3
"""
Test Python decryption on first transaction to compare with JavaScript.
"""
import json
import base64
import sys
import struct

# Add scripts directory to path
sys.path.insert(0, '/Users/ant/Projects/harbour/scripts')

from validate_forensic import (
    parse_keylog_tls13,
    derive_tls13_keys,
    decrypt_tls_record,
    parse_ethernet,
    parse_ip,
    parse_tcp,
    extract_tls_records
)

# Read first transaction
with open('/Users/ant/Projects/harbour/test-fixtures/captures/latest/replay_live_transactions.jsonl', 'r') as f:
    line = f.readline()
    tx = json.loads(line)['data']

print('=== Transaction ===')
print(f"ID: {tx['id']}")
print(f"Protocol: {tx['protocol']}")
print(f"URL: {tx['request']['url']}")
print()

# Parse keylog
keylog_str = tx['forensic_evidence']['keylog']
secrets = parse_keylog_tls13(keylog_str)

if secrets:
    print('=== Secrets ===')
    print(f"Client random: {secrets.client_random.hex()}")
    print(f"Client traffic secret: {secrets.client_traffic_secret.hex()}")
    print(f"Server traffic secret: {secrets.server_traffic_secret.hex()}")
    print()

    # Derive keys
    keys = derive_tls13_keys(secrets)
    print('=== Derived Keys ===')
    print(f"Client key: {keys.client_key.hex()}")
    print(f"Client IV: {keys.client_iv.hex()}")
    print(f"Server key: {keys.server_key.hex()}")
    print(f"Server IV: {keys.server_iv.hex()}")
    print()

# Parse packets
packets = tx['forensic_evidence']['raw_packets']['packets']
client_payloads = []
server_payloads = []

for pkt in packets:
    raw_data = base64.b64decode(pkt['data'])

    # Parse Ethernet
    ethertype, eth_len = parse_ethernet(raw_data)
    if eth_len == 0:
        # No Ethernet, raw IP
        eth_len = 0
        # Try IPv4
        if len(raw_data) > 0 and (raw_data[0] >> 4) == 4:
            ethertype = 0x0800
        elif len(raw_data) > 0 and (raw_data[0] >> 4) == 6:
            ethertype = 0x86dd

    # Parse IP
    protocol, ip_offset, _ = parse_ip(raw_data, eth_len, ethertype)

    # Parse TCP
    if protocol == 6:  # TCP
        tcp_payload, _, _ = parse_tcp(raw_data, ip_offset)
        if len(tcp_payload) > 0:
            if pkt['direction'] == 'client_to_server':
                client_payloads.append(tcp_payload)
            else:
                server_payloads.append(tcp_payload)

# Concatenate streams
client_stream = b''.join(client_payloads)
server_stream = b''.join(server_payloads)

print('=== Streams ===')
print(f"Client stream: {len(client_stream)} bytes from {len(client_payloads)} packets")
print(f"Server stream: {len(server_stream)} bytes from {len(server_payloads)} packets")
print(f"Client stream first 20 bytes: {client_stream[:20].hex()}")
print()

# Extract TLS records
client_records = extract_tls_records(client_stream)
server_records = extract_tls_records(server_stream)

print('=== TLS Records ===')
print(f"Client records: {len(client_records)}")
print(f"Server records: {len(server_records)}")
print()

# Try to decrypt client records
print('=== Client Decryption ===')
client_hint = 0
for i, (content_type, header, ciphertext) in enumerate(client_records, 1):
    type_name = {20: 'CHANGE_CIPHER_SPEC', 21: 'ALERT', 22: 'HANDSHAKE', 23: 'APPLICATION_DATA'}.get(content_type, f'UNKNOWN({content_type})')
    print(f"Record {i}: type={type_name}, size={len(ciphertext)}")
    print(f"  Header: {header.hex()}")
    print(f"  Ciphertext first 20 bytes: {ciphertext[:20].hex()}")

    if content_type == 23:  # APPLICATION_DATA
        plaintext, seq = decrypt_tls_record(header, ciphertext, keys, True, client_hint)
        if plaintext is not None:
            print(f"  ✓ SUCCESS: seq={seq}, plaintext={len(plaintext)} bytes")
            client_hint = seq + 1
        else:
            print(f"  ✗ FAILED")

print()
print('=== Server Decryption ===')
server_hint = 0
for i, (content_type, header, ciphertext) in enumerate(server_records, 1):
    type_name = {20: 'CHANGE_CIPHER_SPEC', 21: 'ALERT', 22: 'HANDSHAKE', 23: 'APPLICATION_DATA'}.get(content_type, f'UNKNOWN({content_type})')
    print(f"Record {i}: type={type_name}, size={len(ciphertext)}")
    print(f"  Header: {header.hex()}")

    if content_type == 23:  # APPLICATION_DATA
        plaintext, seq = decrypt_tls_record(header, ciphertext, keys, False, server_hint)
        if plaintext is not None:
            print(f"  ✓ SUCCESS: seq={seq}, plaintext={len(plaintext)} bytes")
            server_hint = seq + 1
        else:
            print(f"  ✗ FAILED")
