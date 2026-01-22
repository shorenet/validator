#!/usr/bin/env python3
import struct
import hmac
import hashlib

# The client traffic secret from the transaction
client_traffic_secret = bytes.fromhex('7721824958cc550e46868f73117a235d530219c3767fe0a879f5bf21087a86541e13b69021d31c29668b0caabb83e483')

print('Client traffic secret:', client_traffic_secret.hex())
print()

# Build HkdfLabel for "key"
label = b"tls13 key"
context = b""
length = 16

hkdf_label = struct.pack("!H", length)
hkdf_label += struct.pack("!B", len(label)) + label
hkdf_label += struct.pack("!B", len(context)) + context

print('HkdfLabel:', hkdf_label.hex())
print('Length:', len(hkdf_label))
print()

# HKDF-Expand for first iteration
# T(1) = HMAC(PRK, T(0) || info || 0x01)
# where T(0) = empty for first iteration

# Just info || 0x01 for first block
info_with_counter = hkdf_label + b'\x01'
print('Info with counter:', info_with_counter.hex())
print()

# Compute HMAC-SHA256
result = hmac.new(client_traffic_secret, info_with_counter, hashlib.sha256).digest()
print('HMAC result:', result.hex())
print('First 16 bytes (key):', result[:16].hex())
