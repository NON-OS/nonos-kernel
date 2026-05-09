#!/usr/bin/env python3
"""Convert PNG to LZ4-compressed raw pixel format for fast loading."""

import sys
import struct
from pathlib import Path

try:
    from PIL import Image
    import lz4.block
except ImportError:
    print("pip install pillow lz4")
    sys.exit(1)

MAGIC = b"NLZ4"

def convert(png_path: str, out_path: str) -> None:
    img = Image.open(png_path).convert("RGBA")
    w, h = img.size
    raw = img.tobytes()
    compressed = lz4.block.compress(raw, store_size=False)
    header = MAGIC + struct.pack("<III", w, h, len(raw))
    with open(out_path, "wb") as f:
        f.write(header + compressed)
    ratio = len(compressed) / len(raw) * 100
    print(f"{png_path} -> {out_path}: {w}x{h}, {len(raw)}B -> {len(compressed)}B ({ratio:.1f}%)")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input.png> <output.lz4raw>")
        sys.exit(1)
    convert(sys.argv[1], sys.argv[2])
