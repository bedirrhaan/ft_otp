#!/usr/bin/env python3
import sys
import os
import time
import hmac
import hashlib
import struct

PASS = b"ft_otp_secret_key"
MAGIC = b"FTOTP\x01"
PERIOD = 30
DIGITS = 6


def error(msg):
    print(f"./ft_otp: error: {msg}", file=sys.stderr)
    sys.exit(1)


def usage():
    print("Usage: ./ft_otp [-g keyfile | -k ft_otp.key]", file=sys.stderr)
    sys.exit(1)


def is_hex(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def derive_key(length):
    out = b""
    i = 0
    while len(out) < length:
        out += hashlib.sha256(PASS + struct.pack(">I", i)).digest()
        i += 1
    return out[:length]


def encrypt(data):
    key = derive_key(len(data))
    return MAGIC + bytes(a ^ b for a, b in zip(data, key))


def decrypt(blob):
    if not blob.startswith(MAGIC):
        error("invalid or corrupted key file")
    data = blob[len(MAGIC):]
    key = derive_key(len(data))
    return bytes(a ^ b for a, b in zip(data, key))

def hotp(key, counter):
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return binary % (10 ** DIGITS)

def totp(key):
    counter = int(time.time()) // PERIOD
    return hotp(key, counter)


def save_key(path):
    try:
        with open(path, "r") as f:
            raw = f.read().strip()
    except OSError:
        error(f"cannot read file '{path}'")

    raw = "".join(raw.split())

    if len(raw) < 64 or not is_hex(raw) or len(raw) % 2 != 0:
        error("key must be 64 hexadecimal characters.")

    key_bytes = bytes.fromhex(raw)
    with open("ft_otp.key", "wb") as f:
        f.write(encrypt(key_bytes))

    # restrict permissions a bit
    os.chmod("ft_otp.key", 0o600)
    print("Key was successfully saved in ft_otp.key.")


def gen_otp(path):
    try:
        with open(path, "rb") as f:
            blob = f.read()
    except OSError:
        error(f"cannot read file '{path}'")

    key = decrypt(blob)
    code = totp(key)
    print(f"{code:06d}")


def main():
    if len(sys.argv) != 3:
        usage()

    flag, arg = sys.argv[1], sys.argv[2]
    if flag == "-g":
        save_key(arg)
    elif flag == "-k":
        gen_otp(arg)
    else:
        usage()


if __name__ == "__main__":
    main()
