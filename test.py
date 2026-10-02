#!/usr/bin/env python3
import hmac
import hashlib
import struct
import time
import base64
import sys

def totp(key):
    counter = int(time.time()) // 30
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return binary % (10 ** 6)

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "key.hex"
    with open(path, "r") as f:
        hexkey = "".join(f.read().split())

    key = bytes.fromhex(hexkey)
    b32 = base64.b32encode(key).decode()

    print("base32 (google authenticator):", b32)
    print("totp:", f"{totp(key):06d}")

if __name__ == "__main__":
    main()
