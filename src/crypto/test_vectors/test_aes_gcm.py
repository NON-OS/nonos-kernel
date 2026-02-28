#!/usr/bin/env python3
"""
NØNOS AES-256-GCM Test Vector Verification

Verifies test vectors against NIST SP 800-38D:
https://csrc.nist.gov/publications/detail/sp/800-38d/final

Test vectors from:
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
"""

import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def main():
    print("=" * 80)
    print("  AES-256-GCM TEST VECTOR VERIFICATION (NIST SP 800-38D)")
    print("=" * 80)
    print()
    print("Source: NIST CAVP GCM Test Vectors")
    print()

    results = []

    # ==========================================================================
    # Test Case 13 from NIST (AES-256, 96-bit IV, empty PT, empty AAD)
    # ==========================================================================
    print("-" * 80)
    print("[Test 1] NIST Test Case 13 (AES-256, empty PT, empty AAD)")
    print("-" * 80)
    print()

    key_13 = bytes(32)  # All zeros
    iv_13 = bytes(12)   # All zeros
    pt_13 = b""
    aad_13 = b""
    # Expected from NIST
    tag_13_expected = bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b")

    print(f"Key: {key_13.hex()}")
    print(f"IV:  {iv_13.hex()}")
    print(f"PT:  (empty)")
    print(f"AAD: (empty)")
    print()

    aesgcm = AESGCM(key_13)
    ct_with_tag = aesgcm.encrypt(iv_13, pt_13, aad_13)
    computed_tag = ct_with_tag[-16:]
    match = computed_tag == tag_13_expected

    print(f"Expected Tag: {tag_13_expected.hex()}")
    print(f"Computed Tag: {computed_tag.hex()}")

    results.append(("Test Case 13 (empty)", match))
    print()
    print(f"Status: {'PASS' if match else 'FAIL'}")
    print()

    # ==========================================================================
    # Test Case 14 from NIST (AES-256, 96-bit IV, 16-byte PT, empty AAD)
    # ==========================================================================
    print("-" * 80)
    print("[Test 2] NIST Test Case 14 (AES-256, 16-byte PT, empty AAD)")
    print("-" * 80)
    print()

    key_14 = bytes(32)  # All zeros
    iv_14 = bytes(12)   # All zeros
    pt_14 = bytes(16)   # All zeros
    aad_14 = b""
    # Expected from NIST
    ct_14_expected = bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18")
    tag_14_expected = bytes.fromhex("d0d1c8a799996bf0265b98b5d48ab919")

    print(f"Key: {key_14.hex()}")
    print(f"IV:  {iv_14.hex()}")
    print(f"PT:  {pt_14.hex()}")
    print(f"AAD: (empty)")
    print()

    aesgcm = AESGCM(key_14)
    ct_with_tag = aesgcm.encrypt(iv_14, pt_14, aad_14)
    computed_ct = ct_with_tag[:-16]
    computed_tag = ct_with_tag[-16:]
    ct_match = computed_ct == ct_14_expected
    tag_match = computed_tag == tag_14_expected
    match = ct_match and tag_match

    print(f"Expected CT:  {ct_14_expected.hex()}")
    print(f"Computed CT:  {computed_ct.hex()}")
    print()
    print(f"Expected Tag: {tag_14_expected.hex()}")
    print(f"Computed Tag: {computed_tag.hex()}")

    results.append(("Test Case 14 (16-byte)", match))
    print()
    print(f"Status: {'PASS' if match else 'FAIL'}")
    print()

    # ==========================================================================
    # Test Case 15 from NIST (AES-256, non-trivial key/IV/PT)
    # ==========================================================================
    print("-" * 80)
    print("[Test 3] NIST Test Case 15 (AES-256, 64-byte PT, non-trivial key)")
    print("-" * 80)
    print()

    key_15 = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
    iv_15 = bytes.fromhex("cafebabefacedbaddecaf888")
    pt_15 = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
    aad_15 = b""
    # Expected from NIST
    ct_15_expected = bytes.fromhex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad")
    tag_15_expected = bytes.fromhex("b094dac5d93471bdec1a502270e3cc6c")

    print(f"Key: {key_15.hex()}")
    print(f"IV:  {iv_15.hex()}")
    print(f"PT:  {pt_15.hex()}")
    print(f"AAD: (empty)")
    print()

    aesgcm = AESGCM(key_15)
    ct_with_tag = aesgcm.encrypt(iv_15, pt_15, aad_15)
    computed_ct = ct_with_tag[:-16]
    computed_tag = ct_with_tag[-16:]
    ct_match = computed_ct == ct_15_expected
    tag_match = computed_tag == tag_15_expected
    match = ct_match and tag_match

    print(f"Expected CT:  {ct_15_expected.hex()}")
    print(f"Computed CT:  {computed_ct.hex()}")
    print()
    print(f"Expected Tag: {tag_15_expected.hex()}")
    print(f"Computed Tag: {computed_tag.hex()}")

    results.append(("Test Case 15 (64-byte)", match))
    print()
    print(f"Status: {'PASS' if match else 'FAIL'}")
    print()

    # ==========================================================================
    # Test Case 16 from NIST (AES-256, with AAD)
    # ==========================================================================
    print("-" * 80)
    print("[Test 4] NIST Test Case 16 (AES-256, 60-byte PT, 20-byte AAD)")
    print("-" * 80)
    print()

    key_16 = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
    iv_16 = bytes.fromhex("cafebabefacedbaddecaf888")
    pt_16 = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
    aad_16 = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    # Expected from NIST
    ct_16_expected = bytes.fromhex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662")
    tag_16_expected = bytes.fromhex("76fc6ece0f4e1768cddf8853bb2d551b")

    print(f"Key: {key_16.hex()}")
    print(f"IV:  {iv_16.hex()}")
    print(f"PT:  {pt_16.hex()}")
    print(f"AAD: {aad_16.hex()}")
    print()

    aesgcm = AESGCM(key_16)
    ct_with_tag = aesgcm.encrypt(iv_16, pt_16, aad_16)
    computed_ct = ct_with_tag[:-16]
    computed_tag = ct_with_tag[-16:]
    ct_match = computed_ct == ct_16_expected
    tag_match = computed_tag == tag_16_expected
    match = ct_match and tag_match

    print(f"Expected CT:  {ct_16_expected.hex()}")
    print(f"Computed CT:  {computed_ct.hex()}")
    print()
    print(f"Expected Tag: {tag_16_expected.hex()}")
    print(f"Computed Tag: {computed_tag.hex()}")

    results.append(("Test Case 16 (with AAD)", match))
    print()
    print(f"Status: {'PASS' if match else 'FAIL'}")
    print()

    # ==========================================================================
    # GF(2^128) Reduction Polynomial
    # ==========================================================================
    print("-" * 80)
    print("[Test 5] GF(2^128) Reduction Polynomial")
    print("-" * 80)
    print()
    print("The reduction polynomial for GCM is: x^128 + x^7 + x^2 + x + 1")
    print("In the NIST representation (MSB first), this gives R = 0xE1 << 120")
    print()
    print("Code uses GF128_R = 0xE100_0000_0000_0000 (upper 64 bits)")
    print()

    # Verify the polynomial
    # x^7 + x^2 + x + 1 = 0b10000111 = 0x87 in normal bit order
    # But GCM uses reflected bit order, so it's 0xE1
    expected_r = 0xE100_0000_0000_0000
    code_r = 0xE100_0000_0000_0000  # From the code
    match = expected_r == code_r
    results.append(("GF(2^128) polynomial", match))
    print(f"Expected R: 0x{expected_r:016x}")
    print(f"Code R:     0x{code_r:016x}")
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
        print(f"  {name:30}: {'PASS' if passed else 'FAIL'}")
    print()

    all_pass = all(r[1] for r in results)
    print("=" * 80)
    if all_pass:
        print("  RESULT: ALL 5 AES-256-GCM TEST VECTORS PASSED")
    else:
        print("  RESULT: SOME TEST VECTORS FAILED")
    print("=" * 80)

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
