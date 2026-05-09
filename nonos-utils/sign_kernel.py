#!/usr/bin/env python3
"""
NONOS Kernel Signing Tool
Signs kernel binary with Ed25519, appends signature and NONOSIMG footer.
"""
import sys
import struct
from pathlib import Path

FOOTER_MAGIC = b"NONOSIMG"
FOOTER_VERSION = 1
FOOTER_SIZE = 64
HASH_ALG_BLAKE3 = 1
SIG_ALG_ED25519 = 1

def ensure_nacl():
    """Ensure PyNaCl is available."""
    try:
        from nacl.signing import SigningKey
        return SigningKey
    except ImportError:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pynacl", "-q"])
        from nacl.signing import SigningKey
        return SigningKey

def create_footer(kernel_size: int, total_size: int) -> bytes:
    """Create NONOSIMG footer (64 bytes)."""
    footer = bytearray(FOOTER_SIZE)
    footer[0:8] = FOOTER_MAGIC
    footer[8:10] = struct.pack("<H", FOOTER_VERSION)
    footer[10:12] = struct.pack("<H", 0)
    footer[12] = HASH_ALG_BLAKE3
    footer[13] = SIG_ALG_ED25519
    footer[14:16] = struct.pack("<H", 0)
    footer[16:24] = struct.pack("<Q", total_size)
    footer[24:28] = struct.pack("<I", 0)
    footer[28:32] = struct.pack("<I", kernel_size)
    footer[32:36] = struct.pack("<I", kernel_size)
    footer[36:40] = struct.pack("<I", 64)
    footer[40:44] = struct.pack("<I", 0)
    footer[44:48] = struct.pack("<I", 0)
    footer[48:52] = struct.pack("<I", 1)
    return bytes(footer)

def sign_kernel(kernel_path: str, key_path: str, output_path: str) -> None:
    """Sign kernel binary and append Ed25519 signature + footer."""
    SigningKey = ensure_nacl()
    from nacl.encoding import RawEncoder

    kernel_data = Path(kernel_path).read_bytes()
    key_seed = Path(key_path).read_bytes()

    if len(key_seed) != 32:
        raise ValueError(f"Signing key must be 32 bytes, got {len(key_seed)}")

    signing_key = SigningKey(key_seed)
    public_key = signing_key.verify_key

    signed = signing_key.sign(kernel_data, encoder=RawEncoder)
    signature = signed.signature

    if len(signature) != 64:
        raise ValueError(f"Signature must be 64 bytes, got {len(signature)}")

    kernel_size = len(kernel_data)
    total_size = kernel_size + 64 + FOOTER_SIZE
    footer = create_footer(kernel_size, total_size)

    output_data = kernel_data + signature + footer
    Path(output_path).write_bytes(output_data)

    print(f"Kernel: {kernel_size} bytes")
    print(f"Signature: 64 bytes")
    print(f"Footer: {FOOTER_SIZE} bytes (NONOSIMG)")
    print(f"Public key: {public_key.encode().hex()}")
    print(f"Output: {output_path} ({len(output_data)} bytes)")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: sign_kernel.py <kernel> <key> <output>")
        sys.exit(1)
    sign_kernel(sys.argv[1], sys.argv[2], sys.argv[3])
