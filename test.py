#!/usr/bin/env python3
import base64
import hashlib
import hmac
import struct
import sys
import time
from pathlib import Path

try:
    import qrcode
except ImportError:
    qrcode = None


def totp(key):
    counter = int(time.time()) // 30
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return binary % (10 ** 6)


def otpauth_uri(label, secret_b32, issuer="FTOTP"):
    return (
        f"otpauth://totp/{issuer}:{label}?"
        f"secret={secret_b32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    )


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "key.hex"
    try:
        with open(path, "r") as f:
            hexkey = "".join(f.read().split())
    except FileNotFoundError:
        print("Error: File not found")
        return

    if len(hexkey) % 2 != 0 or len(hexkey) == 0:
        print("Error: invalid hex key")
        return

    key = bytes.fromhex(hexkey)
    secret_b32 = base64.b32encode(key).decode("ascii").rstrip("=")
    label = Path(path).stem
    uri = otpauth_uri(label, secret_b32)

    print("otpauth uri:", uri)
    print("base32:", secret_b32)
    print("totp:", f"{totp(key):06d}")

    if qrcode is None:
        print("Install with: pip install qrcode[pil]")
        return

    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    out_path = Path(f"{label}.png")
    img.save(out_path)
    print(f"QR saved to: {out_path}")


if __name__ == "__main__":
    main()
