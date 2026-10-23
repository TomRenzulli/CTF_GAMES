#!/usr/bin/env python3
"""Generate all static challenge files for BERA Cyber Training Academy."""
import base64
import os
import struct
import zlib

import pathlib
OUT = str(pathlib.Path(__file__).parent.resolve())

# ── Flag 02: hex-encoded flag hidden in a text file ──────────────────────────
flag02 = "FLAG{hex_decoded_you_found_me}"
hex_str = flag02.encode().hex()
with open(f"{OUT}/signal.txt", "w") as f:
    f.write("TRANSMISSION INTERCEPT LOG\n")
    f.write("="*40 + "\n")
    f.write("Timestamp: 2026-10-15T09:41:22Z\n")
    f.write("Source: Unknown\n")
    f.write("Message (encoded): ")
    f.write(hex_str + "\n")
    f.write("="*40 + "\n")
    f.write("Tip: Each pair of characters is a hex byte. Try: echo '...' | xxd -r -p\n")

# ── Flag 03: binary-encoded flag ─────────────────────────────────────────────
flag03 = "FLAG{bits_and_bytes_101}"
binary_str = " ".join(format(ord(c), '08b') for c in flag03)
with open(f"{OUT}/binary_message.txt", "w") as f:
    f.write("BINARY TRANSMISSION RECEIVED\n")
    f.write("-"*40 + "\n")
    f.write(binary_str + "\n")
    f.write("-"*40 + "\n")
    f.write("Tip: Each group of 8 bits is one character (ASCII). 01000001 = A\n")

# ── Flag 06: file with flag buried in strings output ─────────────────────────
flag06 = "FLAG{strings_reveals_all_secrets}"
with open(f"{OUT}/mystery.bin", "wb") as f:
    # Write random-ish bytes, then embed the flag, then more junk
    junk1 = bytes([0x89, 0x50, 0x4e, 0x47, 0x00, 0x00, 0xFF, 0xFE] * 20)
    junk2 = bytes(range(256)) * 3
    f.write(junk1)
    f.write(b"\x00\x00\x00")
    f.write(flag06.encode())
    f.write(b"\x00\x00\x00")
    f.write(junk2)
    f.write(b"JUNK DATA JUNK DATA JUNK DATA\x00\x00")
    f.write(b"SOME OTHER STRING HERE\x00")

# ── Flag 07: file where `file` command matters + strings ─────────────────────
flag07 = "FLAG{file_command_knows_all}"
# Make a valid ZIP with flag inside, but named .txt
import zipfile, io
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as zf:
    zf.writestr("readme.txt", f"You found the hidden archive!\nFlag: {flag07}\n")
buf.seek(0)
with open(f"{OUT}/definitely_a_text_file.txt", "wb") as f:
    f.write(buf.read())

# ── Flag 14: PNG with flag in EXIF/metadata comment ──────────────────────────
flag14 = "FLAG{metadata_hides_in_plain_sight}"
# Build a minimal valid PNG with a tEXt chunk containing the flag
def make_png_with_text(width=10, height=10, text_key="Comment", text_value=""):
    def chunk(name, data):
        c = name + data
        return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

    sig = b'\x89PNG\r\n\x1a\n'
    ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)
    ihdr = chunk(b'IHDR', ihdr_data)

    # minimal image data - red pixels
    raw = b''
    for y in range(height):
        raw += b'\x00' + b'\xff\x00\x00' * width
    compressed = zlib.compress(raw)
    idat = chunk(b'IDAT', compressed)

    text_payload = text_key.encode() + b'\x00' + text_value.encode()
    text_chunk = chunk(b'tEXt', text_payload)

    iend = chunk(b'IEND', b'')
    return sig + ihdr + text_chunk + idat + iend

png_data = make_png_with_text(text_key="Author", text_value=f"BERA Cyber | Flag: {flag14}")
with open(f"{OUT}/training_badge.png", "wb") as f:
    f.write(png_data)

# ── Flag 15: file with wrong extension (JPEG named .pdf) ─────────────────────
flag15 = "FLAG{magic_bytes_dont_lie}"
# Minimal valid JPEG
jpeg_data = bytes([
    0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    0xFF, 0xFE,  # Comment marker
]) + struct.pack('>H', len(flag15) + 2) + flag15.encode() + bytes([0xFF, 0xD9])
with open(f"{OUT}/report.pdf", "wb") as f:
    f.write(jpeg_data)

print("All challenge files generated.")
for fn in sorted(os.listdir(OUT)):
    if fn != "generate.py":
        size = os.path.getsize(f"{OUT}/{fn}")
        print(f"  {fn:40s} {size:6d} bytes")
