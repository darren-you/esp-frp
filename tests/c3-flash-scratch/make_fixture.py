#!/usr/bin/env python3
"""Generate a public, deterministic full-length FRP AEAD record for C3 QEMU."""

import hashlib
from pathlib import Path
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: make_fixture.py OUTPUT_DIRECTORY")
    output = Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=True)
    key = bytes((index * 17 + 3) & 0xFF for index in range(32))
    nonce = bytes(range(12))
    plaintext = bytes((index * 29 + 7) & 0xFF for index in range(65536))
    header = (len(plaintext) + 16).to_bytes(4, "big")
    wire = nonce + header + AESGCM(key).encrypt(nonce, plaintext, nonce + header)
    if len(wire) != 65568:
        raise RuntimeError("unexpected AEAD record length")
    (output / "full-record.bin").write_bytes(wire)
    lines = [
        "    " + " ".join(f"0x{byte:02x}," for byte in wire[offset : offset + 16])
        for offset in range(0, len(wire), 16)
    ]
    (output / "full-record.inc").write_text("\n".join(lines) + "\n", encoding="ascii")
    print(f"C3 Flash fixture sha256={hashlib.sha256(wire).hexdigest()}")


if __name__ == "__main__":
    main()
