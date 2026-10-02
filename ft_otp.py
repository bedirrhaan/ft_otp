#!/usr/bin/env python3
import sys
import os
import time
import hmac
import hashlib
import struct
import base64

PASS = b"ft_otp_secret_key"
MAGIC = b"FTOTP\x01"
PERIOD = 30
DIGITS = 6
QR_FILE = "ft_otp.png"


def error(msg):
    print(f"./ft_otp: error: {msg}", file=sys.stderr)
    sys.exit(1)


def usage():
    print("Usage: ./ft_otp [-g keyfile | -k keyfile]", file=sys.stderr)
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


def seconds_left():
    return PERIOD - (int(time.time()) % PERIOD)


def to_base32(key_bytes):
    return base64.b32encode(key_bytes).decode().rstrip("=")


def otpauth_uri(key_bytes):
    secret = to_base32(key_bytes)
    return (
        "otpauth://totp/ft_otp:user"
        f"?secret={secret}&issuer=ft_otp"
        f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD}"
    )


# bonus: QR code with seed (base32) for authenticator apps
def make_qr(key_bytes):
    uri = otpauth_uri(key_bytes)
    try:
        import qrcode
    except ImportError:
        print("QR skipped: pip install qrcode pillow")
        print("seed (base32):", to_base32(key_bytes))
        print("URI:", uri)
        return

    qr = qrcode.QRCode(border=2)
    qr.add_data(uri)
    qr.make(fit=True)

    print("QR (scan with authenticator):")
    qr.print_ascii(invert=True)

    try:
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(QR_FILE)
        print(f"QR saved in {QR_FILE}")
    except Exception:
        print("PNG not saved (need pillow)")

    print("seed (base32):", to_base32(key_bytes))


# bonus: graphic interface
def run_gui(key):
    try:
        import tkinter as tk
    except ImportError:
        print("GUI skipped: tkinter not available")
        return

    root = tk.Tk()
    root.title("ft_otp")
    root.geometry("320x220")
    root.resizable(False, False)

    tk.Label(root, text="ft_otp", font=("Courier", 16, "bold")).pack(pady=(16, 4))
    code_lbl = tk.Label(root, text="000000", font=("Courier", 36, "bold"))
    code_lbl.pack(pady=8)
    time_lbl = tk.Label(root, text="", font=("Courier", 12))
    time_lbl.pack()

    bar = tk.Canvas(root, width=260, height=12, highlightthickness=0)
    bar.pack(pady=12)
    bar_rect = bar.create_rectangle(0, 0, 260, 12, fill="#333333", width=0)

    def tick():
        code_lbl.config(text=f"{totp(key):06d}")
        left = seconds_left()
        time_lbl.config(text=f"{left}s left")
        bar.coords(bar_rect, 0, 0, int(260 * (left / PERIOD)), 12)
        bar.itemconfig(bar_rect, fill="#2a9d8f" if left > 5 else "#e76f51")
        root.after(200, tick)

    tick()
    root.mainloop()


def write_key(key_bytes):
    with open("ft_otp.key", "wb") as f:
        f.write(encrypt(key_bytes))
    os.chmod("ft_otp.key", 0o600)


def read_key_file(path):
    try:
        with open(path, "rb") as f:
            blob = f.read()
    except OSError:
        error(f"cannot read file '{path}'")
    return decrypt(blob)


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
    write_key(key_bytes)
    print("Key was successfully saved in ft_otp.key.")

    # bonus
    make_qr(key_bytes)
    run_gui(key_bytes)


def gen_otp(path):
    key = read_key_file(path)
    print(f"{totp(key):06d}")


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
