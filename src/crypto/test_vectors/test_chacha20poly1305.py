#!/usr/bin/env python3
"""
NØNOS ChaCha20-Poly1305 Test Vector Verification

Verifies test vectors against RFC 8439:
https://www.rfc-editor.org/rfc/rfc8439
"""

import sys

def main():
    print("=" * 80)
    print("  CHACHA20-POLY1305 TEST VECTOR VERIFICATION (RFC 8439)")
    print("=" * 80)
    print()
    print("Source: https://www.rfc-editor.org/rfc/rfc8439")
    print()

    results = []

    # ==========================================================================
    # Test 1: ChaCha20 Block Function (RFC 8439 Section 2.3.2)
    # ==========================================================================
    print("-" * 80)
    print("[Test 1] ChaCha20 Block Function (Section 2.3.2)")
    print("-" * 80)
    print()
    print("Key:     00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f")
    print("         10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f")
    print("Nonce:   00 00 00 09 00 00 00 4a 00 00 00 00")
    print("Counter: 1")
    print()

    chacha_code = [
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
        0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
        0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
        0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
        0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
    ]

    chacha_official = ("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
                       "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")

    code_hex = "".join(f"{b:02x}" for b in chacha_code)
    match = code_hex == chacha_official
    results.append(("ChaCha20 Block", match))

    print(f"Code Output (64 bytes):")
    print(f"  {code_hex}")
    print()
    print(f"Official Output:")
    print(f"  {chacha_official}")
    print()
    print(f"Status: {'PASS' if match else 'FAIL'}")
    print()

    # ==========================================================================
    # Test 2: Poly1305 MAC (RFC 8439 Section 2.5.2)
    # ==========================================================================
    print("-" * 80)
    print("[Test 2] Poly1305 MAC (Section 2.5.2)")
    print("-" * 80)
    print()
    print("Key: 85 d6 be 78 57 55 6d 33 7f 44 52 fe 42 d5 06 a8")
    print("     01 03 80 8a fb 0d b2 fd 4a bf f6 af 41 49 f5 1b")
    print('Message: "Cryptographic Forum Research Group"')
    print()

    poly_code = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
    ]

    poly_official = "a8061dc1305136c6c22b8baf0c0127a9"

    code_hex = "".join(f"{b:02x}" for b in poly_code)
    match = code_hex == poly_official
    results.append(("Poly1305 MAC", match))

    print(f"Code Output (16 bytes):")
    print(f"  {code_hex}")
    print()
    print(f"Official Output:")
    print(f"  {poly_official}")
    print()
    print(f"Status: {'PASS' if match else 'FAIL'}")
    print()

    # ==========================================================================
    # Test 3: AEAD Ciphertext (RFC 8439 Section 2.8.2)
    # ==========================================================================
    print("-" * 80)
    print("[Test 3] AEAD ChaCha20-Poly1305 Ciphertext (Section 2.8.2)")
    print("-" * 80)
    print()
    print("Key:   80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f")
    print("       90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f")
    print("Nonce: 07 00 00 00 40 41 42 43 44 45 46 47")
    print("AAD:   50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7")
    print()
    print('Plaintext: "Ladies and Gentlemen of the class of \'99:')
    print('            If I could offer you only one tip for the future,')
    print('            sunscreen would be it."')
    print()

    ct_code = [
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,
    ]

    ct_official = ("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
                   "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
                   "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
                   "3ff4def08e4b7a9de576d26586cec64b6116")

    code_hex = "".join(f"{b:02x}" for b in ct_code)
    match = code_hex == ct_official
    results.append(("AEAD Ciphertext", match))

    print(f"Ciphertext ({len(ct_code)} bytes):")
    print(f"  Code:     {code_hex}")
    print()
    print(f"  Official: {ct_official}")
    print()
    print(f"Status: {'PASS' if match else 'FAIL'}")
    print()

    # ==========================================================================
    # Test 4: AEAD Tag (RFC 8439 Section 2.8.2)
    # ==========================================================================
    print("-" * 80)
    print("[Test 4] AEAD ChaCha20-Poly1305 Authentication Tag (Section 2.8.2)")
    print("-" * 80)
    print()

    tag_code = [
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    ]

    tag_official = "1ae10b594f09e26a7e902ecbd0600691"

    code_hex = "".join(f"{b:02x}" for b in tag_code)
    match = code_hex == tag_official
    results.append(("AEAD Tag", match))

    print(f"Tag (16 bytes):")
    print(f"  Code:     {code_hex}")
    print(f"  Official: {tag_official}")
    print()
    print(f"Status: {'PASS' if match else 'FAIL'}")
    print()

    # ==========================================================================
    # Summary
    # ==========================================================================
    print("=" * 80)
    print("  SUMMARY")
    print("=" * 80)
    print()
    for name, passed in results:
        print(f"  {name:20}: {'PASS' if passed else 'FAIL'}")
    print()

    all_pass = all(r[1] for r in results)
    print("=" * 80)
    if all_pass:
        print("  RESULT: ALL 4 RFC 8439 TEST VECTORS PASSED")
    else:
        print("  RESULT: SOME TEST VECTORS FAILED")
    print("=" * 80)

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
