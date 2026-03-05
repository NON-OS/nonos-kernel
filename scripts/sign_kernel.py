#!/usr/bin/env python3
"""
NONOS Kernel Signing Tool
Signs kernel binary with Ed25519 and appends 64-byte signature.
"""
import sys
from pathlib import Path

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

def sign_kernel(kernel_path: str, key_path: str, output_path: str) -> None:
    """Sign kernel binary and append Ed25519 signature."""
    SigningKey = ensure_nacl()
    from nacl.encoding import RawEncoder

    kernel_data = Path(kernel_path).read_bytes()
    key_seed = Path(key_path).read_bytes()

    if len(key_seed) != 32:
        raise ValueError(f"Signing key must be 32 bytes, got {len(key_seed)}")

    signing_key = SigningKey(key_seed)
    public_key = signing_key.verify_key

    # Sign raw kernel data directly
    signed = signing_key.sign(kernel_data, encoder=RawEncoder)
    signature = signed.signature

    if len(signature) != 64:
        raise ValueError(f"Signature must be 64 bytes, got {len(signature)}")

    # Append signature to kernel
    output_data = kernel_data + signature
    Path(output_path).write_bytes(output_data)

    print(f"Kernel: {len(kernel_data)} bytes")
    print(f"Public key: {public_key.encode().hex()}")
    print(f"Signature: {signature[:16].hex()}...")
    print(f"Output: {output_path} ({len(output_data)} bytes)")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: sign_kernel.py <kernel> <key> <output>")
        sys.exit(1)
    sign_kernel(sys.argv[1], sys.argv[2], sys.argv[3])
