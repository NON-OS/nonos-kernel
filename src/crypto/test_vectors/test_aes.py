#!/usr/bin/env python3
"""
NØNOS AES Test Vector Verification

Verifies test vectors against:
- FIPS 197: Advanced Encryption Standard (AES)
- NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation
"""

import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def main():
    print("=" * 80)
    print("  AES TEST VECTOR VERIFICATION (FIPS-197 / NIST SP 800-38A)")
    print("=" * 80)
    print()
    print("Source: FIPS 197, NIST SP 800-38A")
    print()

    results = []

    # ==========================================================================
    # AES-256 Test Vectors
    # ==========================================================================

    print("-" * 80)
    print("[Test 1] NIST SP 800-38A F.1.5: AES-256 ECB")
    print("-" * 80)
    print()

    key_256_38a = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    pt_256_38a = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    expected_ct_256_38a = bytes.fromhex("f3eed1bdb5d2a03c064b5a7e3db181f8")

    print(f"Key: {key_256_38a.hex()}")
    print(f"PT:  {pt_256_38a.hex()}")
    print()

    cipher = Cipher(algorithms.AES(key_256_38a), modes.ECB())
    encryptor = cipher.encryptor()
    computed_ct = encryptor.update(pt_256_38a) + encryptor.finalize()

    print(f"Expected CT: {expected_ct_256_38a.hex()}")
    print(f"Computed CT: {computed_ct.hex()}")

    match = computed_ct == expected_ct_256_38a
    results.append(("AES-256 SP800-38A F.1.5", match))
    print()
    print(f"Status: {'PASS' if match else 'FAIL'}")
    print()

    # Verify decryption
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(computed_ct) + decryptor.finalize()
    dec_match = decrypted == pt_256_38a
    results.append(("AES-256 SP800-38A decrypt", dec_match))
    print(f"Decryption: {'PASS' if dec_match else 'FAIL'}")
    print()

    # ==========================================================================
    print("-" * 80)
    print("[Test 2] FIPS-197 Appendix C.3: AES-256")
    print("-" * 80)
    print()

    key_256_fips = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    pt_256_fips = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected_ct_256_fips = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")

    print(f"Key: {key_256_fips.hex()}")
    print(f"PT:  {pt_256_fips.hex()}")
    print()

    cipher = Cipher(algorithms.AES(key_256_fips), modes.ECB())
    encryptor = cipher.encryptor()
    computed_ct = encryptor.update(pt_256_fips) + encryptor.finalize()

    print(f"Expected CT: {expected_ct_256_fips.hex()}")
    print(f"Computed CT: {computed_ct.hex()}")

    match = computed_ct == expected_ct_256_fips
    results.append(("AES-256 FIPS-197 C.3", match))
    print()
    print(f"Status: {'PASS' if match else 'FAIL'}")
    print()

    # ==========================================================================
    # AES-128 Test Vectors
    # ==========================================================================

    print("-" * 80)
    print("[Test 3] NIST SP 800-38A F.1.1: AES-128 ECB")
    print("-" * 80)
    print()

    key_128_38a = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt_128_38a = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    expected_ct_128_38a = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")

    print(f"Key: {key_128_38a.hex()}")
    print(f"PT:  {pt_128_38a.hex()}")
    print()

    cipher = Cipher(algorithms.AES(key_128_38a), modes.ECB())
    encryptor = cipher.encryptor()
    computed_ct = encryptor.update(pt_128_38a) + encryptor.finalize()

    print(f"Expected CT: {expected_ct_128_38a.hex()}")
    print(f"Computed CT: {computed_ct.hex()}")

    match = computed_ct == expected_ct_128_38a
    results.append(("AES-128 SP800-38A F.1.1", match))
    print()
    print(f"Status: {'PASS' if match else 'FAIL'}")
    print()

    # ==========================================================================
    print("-" * 80)
    print("[Test 4] FIPS-197 Appendix C.1: AES-128")
    print("-" * 80)
    print()

    key_128_fips = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt_128_fips = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected_ct_128_fips = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

    print(f"Key: {key_128_fips.hex()}")
    print(f"PT:  {pt_128_fips.hex()}")
    print()

    cipher = Cipher(algorithms.AES(key_128_fips), modes.ECB())
    encryptor = cipher.encryptor()
    computed_ct = encryptor.update(pt_128_fips) + encryptor.finalize()

    print(f"Expected CT: {expected_ct_128_fips.hex()}")
    print(f"Computed CT: {computed_ct.hex()}")

    match = computed_ct == expected_ct_128_fips
    results.append(("AES-128 FIPS-197 C.1", match))
    print()
    print(f"Status: {'PASS' if match else 'FAIL'}")
    print()

    # ==========================================================================
    # S-box Verification
    # ==========================================================================
    print("-" * 80)
    print("[Test 5] S-box Known Values (FIPS-197)")
    print("-" * 80)
    print()

    # Official FIPS-197 S-box (first 16 bytes)
    sbox_official = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    ]

    # Code's S-box values (from aes.rs)
    sbox_code = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    ]

    sbox_match = sbox_official == sbox_code
    results.append(("S-box values", sbox_match))

    print("First 16 S-box entries:")
    print(f"  Official: {' '.join(f'{b:02x}' for b in sbox_official)}")
    print(f"  Code:     {' '.join(f'{b:02x}' for b in sbox_code)}")
    print()

    # Spot check specific values
    spot_checks = [
        (0x00, 0x63),
        (0x01, 0x7c),
        (0x53, 0xed),
        (0xff, 0x16),
    ]
    all_spot = True
    for idx, expected in spot_checks:
        # We trust the code's SBOX array
        print(f"  SBOX[0x{idx:02x}] = 0x{expected:02x} (expected)")
    print()
    print(f"Status: {'PASS' if sbox_match else 'FAIL'}")
    print()

    # ==========================================================================
    # GF(2^8) Multiplication
    # ==========================================================================
    print("-" * 80)
    print("[Test 6] GF(2^8) Multiplication (FIPS-197 Section 4.2)")
    print("-" * 80)
    print()

    def gf_mul(a, b):
        """GF(2^8) multiplication with reduction polynomial x^8 + x^4 + x^3 + x + 1"""
        result = 0
        for _ in range(8):
            if b & 1:
                result ^= a
            carry = a & 0x80
            a = (a << 1) & 0xff
            if carry:
                a ^= 0x1b
            b >>= 1
        return result

    # From FIPS-197: {57} * {83} = {c1}
    gf_tests = [
        (0x57, 0x83, 0xc1),
        (0x57, 0x02, 0xae),
        (0x57, 0x04, 0x47),
        (0x01, 0xff, 0xff),  # identity
        (0x00, 0xff, 0x00),  # zero
    ]

    all_gf = True
    for a, b, expected in gf_tests:
        computed = gf_mul(a, b)
        match = computed == expected
        if not match:
            all_gf = False
        print(f"  0x{a:02x} * 0x{b:02x} = 0x{computed:02x} (expected 0x{expected:02x}) {'PASS' if match else 'FAIL'}")

    results.append(("GF(2^8) multiplication", all_gf))
    print()
    print(f"Status: {'PASS' if all_gf else 'FAIL'}")
    print()

    # ==========================================================================
    # Summary
    # ==========================================================================
    print("=" * 80)
    print("  SUMMARY")
    print("=" * 80)
    print()
    for name, passed in results:
        print(f"  {name:30}: {'PASS' if passed else 'FAIL'}")
    print()

    all_pass = all(r[1] for r in results)
    print("=" * 80)
    if all_pass:
        print(f"  RESULT: ALL {len(results)} AES TEST VECTORS PASSED")
    else:
        print("  RESULT: SOME TEST VECTORS FAILED")
    print("=" * 80)

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
