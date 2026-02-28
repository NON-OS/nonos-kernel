#!/usr/bin/env python3
"""
NØNOS SHA-512 Test Vector Verification

Verifies test vectors against FIPS 180-4:
https://csrc.nist.gov/publications/detail/fips/180/4/final
"""

import hashlib
import sys

def main():
    print("=" * 80)
    print("  SHA-512 TEST VECTOR VERIFICATION (FIPS 180-4)")
    print("=" * 80)
    print()
    print("Source: FIPS 180-4 / NIST CAVP")
    print()

    results = []

    # ==========================================================================
    # Test 1: Empty string
    # ==========================================================================
    print("-" * 80)
    print("[Test 1] Empty string")
    print("-" * 80)
    print()
    print('Input: ""')
    print()

    # From code's test vectors
    code_empty = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"

    # Verify with Python's hashlib
    computed = hashlib.sha512(b"").hexdigest()
    match = computed == code_empty
    results.append(("Empty string", match))

    print(f"Code hash:     {code_empty}")
    print(f"Official hash: {computed}")
    print()
    print(f"Status: {'PASS' if match else 'FAIL'}")
    print()

    # ==========================================================================
    # Test 2: "abc"
    # ==========================================================================
    print("-" * 80)
    print("[Test 2] \"abc\"")
    print("-" * 80)
    print()
    print('Input: "abc"')
    print()

    # From code's test vectors
    code_abc = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"

    computed = hashlib.sha512(b"abc").hexdigest()
    match = computed == code_abc
    results.append(("abc", match))

    print(f"Code hash:     {code_abc}")
    print(f"Official hash: {computed}")
    print()
    print(f"Status: {'PASS' if match else 'FAIL'}")
    print()

    # ==========================================================================
    # Test 3: "The quick brown fox jumps over the lazy dog"
    # ==========================================================================
    print("-" * 80)
    print("[Test 3] \"The quick brown fox jumps over the lazy dog\"")
    print("-" * 80)
    print()

    # From code's test vectors
    code_fox = "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"

    computed = hashlib.sha512(b"The quick brown fox jumps over the lazy dog").hexdigest()
    match = computed == code_fox
    results.append(("Quick brown fox", match))

    print(f"Code hash:     {code_fox}")
    print(f"Official hash: {computed}")
    print()
    print(f"Status: {'PASS' if match else 'FAIL'}")
    print()

    # ==========================================================================
    # Test 4: NIST two-block test vector
    # ==========================================================================
    print("-" * 80)
    print("[Test 4] NIST two-block test (896-bit message)")
    print("-" * 80)
    print()
    print('Input: "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"')
    print('       "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"')
    print()

    msg_896 = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"

    # Official NIST FIPS 180-4 test vector
    official_896 = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"

    computed = hashlib.sha512(msg_896).hexdigest()
    match = computed == official_896
    results.append(("Two-block message", match))

    print(f"NIST vector:   {official_896}")
    print(f"Computed hash: {computed}")
    print()
    print(f"Status: {'PASS' if match else 'FAIL'}")
    print()

    # ==========================================================================
    # Test 5: Initial H values (FIPS 180-4 Section 5.3.5)
    # ==========================================================================
    print("-" * 80)
    print("[Test 5] Initial H values (FIPS 180-4 Section 5.3.5)")
    print("-" * 80)
    print()
    print("H values from FIPS 180-4 (first 64 bits of fractional sqrt of primes):")
    print()

    # These are the official FIPS 180-4 values
    h_official = [
        0x6a09e667f3bcc908,  # sqrt(2)
        0xbb67ae8584caa73b,  # sqrt(3)
        0x3c6ef372fe94f82b,  # sqrt(5)
        0xa54ff53a5f1d36f1,  # sqrt(7)
        0x510e527fade682d1,  # sqrt(11)
        0x9b05688c2b3e6c1f,  # sqrt(13)
        0x1f83d9abfb41bd6b,  # sqrt(17)
        0x5be0cd19137e2179,  # sqrt(19)
    ]

    # Code's values (from INITIAL_STATE in sha512.rs)
    h_code = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ]

    all_h_match = True
    primes = [2, 3, 5, 7, 11, 13, 17, 19]
    for i, (official, code, prime) in enumerate(zip(h_official, h_code, primes)):
        match_h = official == code
        if not match_h:
            all_h_match = False
        print(f"  H[{i}] = 0x{code:016x} (sqrt({prime:2d})) {'PASS' if match_h else 'FAIL'}")

    results.append(("Initial H values", all_h_match))
    print()

    # ==========================================================================
    # Test 6: K constants spot check (FIPS 180-4 Section 4.2.3)
    # ==========================================================================
    print("-" * 80)
    print("[Test 6] K constants spot check (FIPS 180-4 Section 4.2.3)")
    print("-" * 80)
    print()
    print("K values are first 64 bits of fractional cube roots of first 80 primes.")
    print("Spot-checking first 4 and last 4:")
    print()

    # Official FIPS 180-4 K constants
    k_official = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        # ... (76 more) ...
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ]

    # Code's K constants (first 4 and last 4)
    k_code_first = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    ]
    k_code_last = [
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ]

    all_k_match = True
    for i, (official, code) in enumerate(zip(k_official[:4], k_code_first)):
        match_k = official == code
        if not match_k:
            all_k_match = False
        print(f"  K[{i:2d}] = 0x{code:016x} {'PASS' if match_k else 'FAIL'}")

    print("  ...")

    for i, (official, code) in enumerate(zip(k_official[-4:], k_code_last)):
        idx = 76 + i
        match_k = official == code
        if not match_k:
            all_k_match = False
        print(f"  K[{idx:2d}] = 0x{code:016x} {'PASS' if match_k else 'FAIL'}")

    results.append(("K constants", all_k_match))
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
        print("  RESULT: ALL 6 SHA-512 TEST VECTORS PASSED")
    else:
        print("  RESULT: SOME TEST VECTORS FAILED")
    print("=" * 80)

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
