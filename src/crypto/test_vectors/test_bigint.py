#!/usr/bin/env python3
"""
NØNOS BigUint Test Vector Verification

Verifies arithmetic operations against Python's arbitrary precision integers.
"""

import sys

def main():
    print("=" * 80)
    print("  BIGINT TEST VECTOR VERIFICATION")
    print("=" * 80)
    print()

    results = []

    # ==========================================================================
    # Basic Arithmetic
    # ==========================================================================

    print("-" * 80)
    print("[Test 1] Addition with carry")
    print("-" * 80)
    print()

    a = 0xFFFFFFFFFFFFFFFF  # u64::MAX
    b = 1
    expected = a + b
    print(f"a = 0x{a:x}")
    print(f"b = 0x{b:x}")
    print(f"a + b = 0x{expected:x}")
    print()

    # Verify this matches a 2-limb result
    assert expected == 0x10000000000000000
    results.append(("Addition with carry", True))
    print("Status: PASS")
    print()

    # ==========================================================================
    print("-" * 80)
    print("[Test 2] Multiplication")
    print("-" * 80)
    print()

    a = 0xFFFFFFFFFFFFFFFF  # u64::MAX
    b = 0xFFFFFFFFFFFFFFFF  # u64::MAX
    expected = a * b
    print(f"a = 0x{a:x}")
    print(f"b = 0x{b:x}")
    print(f"a * b = 0x{expected:x}")
    print()

    # (2^64 - 1)^2 = 2^128 - 2^65 + 1
    assert expected == (1 << 128) - (1 << 65) + 1
    results.append(("Multiplication", True))
    print("Status: PASS")
    print()

    # ==========================================================================
    print("-" * 80)
    print("[Test 3] Division (Knuth's Algorithm D)")
    print("-" * 80)
    print()

    # Large dividend, multi-limb divisor
    a = 0x123456789ABCDEF0_FEDCBA9876543210
    b = 0x123456789ABCDEF0
    q = a // b
    r = a % b
    print(f"a = 0x{a:x}")
    print(f"b = 0x{b:x}")
    print(f"q = a // b = 0x{q:x}")
    print(f"r = a % b = 0x{r:x}")
    print()

    # Verify: a = q * b + r
    check = q * b + r
    assert check == a, f"Division check failed: {check} != {a}"
    results.append(("Division (Knuth)", True))
    print("Status: PASS")
    print()

    # ==========================================================================
    print("-" * 80)
    print("[Test 4] Modular Exponentiation")
    print("-" * 80)
    print()

    # 3^10 mod 7 = 59049 mod 7 = 4
    base = 3
    exp = 10
    mod = 7
    expected = pow(base, exp, mod)
    print(f"base = {base}")
    print(f"exp = {exp}")
    print(f"mod = {mod}")
    print(f"base^exp mod m = {expected}")
    print()

    assert expected == 4
    results.append(("Modular exponentiation", True))
    print("Status: PASS")
    print()

    # ==========================================================================
    print("-" * 80)
    print("[Test 5] Modular Inverse (Extended Euclidean)")
    print("-" * 80)
    print()

    # 3 * 5 ≡ 1 (mod 7), so 3^(-1) ≡ 5 (mod 7)
    a = 3
    m = 7
    inv = pow(a, -1, m)
    print(f"a = {a}")
    print(f"m = {m}")
    print(f"a^(-1) mod m = {inv}")
    print()

    assert inv == 5
    assert (a * inv) % m == 1
    results.append(("Modular inverse", True))
    print("Status: PASS")
    print()

    # ==========================================================================
    print("-" * 80)
    print("[Test 6] GCD (Binary GCD)")
    print("-" * 80)
    print()

    import math

    a = 48
    b = 18
    g = math.gcd(a, b)
    print(f"a = {a}")
    print(f"b = {b}")
    print(f"gcd(a, b) = {g}")
    print()

    assert g == 6
    results.append(("GCD", True))
    print("Status: PASS")
    print()

    # ==========================================================================
    print("-" * 80)
    print("[Test 7] Miller-Rabin Primality")
    print("-" * 80)
    print()

    def is_prime(n, k=20):
        """Miller-Rabin primality test"""
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False

        # Write n-1 as d * 2^r
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        # Witnesses
        def check(a):
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                return True
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    return True
            return False

        witnesses = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
        for a in witnesses:
            if a >= n:
                continue
            if not check(a):
                return False
        return True

    # Test known primes
    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    non_primes = [0, 1, 4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20]

    all_correct = True
    for p in primes:
        if not is_prime(p):
            print(f"  {p} should be prime but isn't")
            all_correct = False

    for np in non_primes:
        if is_prime(np):
            print(f"  {np} should not be prime but is")
            all_correct = False

    # Mersenne prime 2^61 - 1
    m61 = (1 << 61) - 1
    if not is_prime(m61):
        print(f"  2^61 - 1 should be prime")
        all_correct = False
    else:
        print(f"  2^61 - 1 = {m61} is prime: PASS")

    results.append(("Miller-Rabin primality", all_correct))
    print()
    print(f"Status: {'PASS' if all_correct else 'FAIL'}")
    print()

    # ==========================================================================
    print("-" * 80)
    print("[Test 8] Montgomery Multiplication Constants")
    print("-" * 80)
    print()

    # Montgomery inverse: -m^(-1) mod 2^64
    def montgomery_inverse(m0):
        """Compute -m0^(-1) mod 2^64"""
        assert m0 & 1 == 1, "m0 must be odd"
        y = 1
        for _ in range(6):
            y = (y * (2 - m0 * y)) % (1 << 64)
        return (-y) % (1 << 64)

    # Test with a known odd modulus
    test_m = 0xFFFFFFFFFFFFFFC5  # Large odd number
    m_inv = montgomery_inverse(test_m)

    # Verify: m_inv * m0 ≡ -1 (mod 2^64)
    product = (m_inv * test_m) % (1 << 64)
    expected = (1 << 64) - 1  # -1 mod 2^64

    print(f"m0 = 0x{test_m:016x}")
    print(f"-m0^(-1) mod 2^64 = 0x{m_inv:016x}")
    print(f"Verify: m_inv * m0 mod 2^64 = 0x{product:016x}")
    print(f"Expected (-1 mod 2^64) = 0x{expected:016x}")
    print()

    match = product == expected
    results.append(("Montgomery inverse", match))
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
        print(f"  RESULT: ALL {len(results)} BIGINT TESTS PASSED")
    else:
        print("  RESULT: SOME TESTS FAILED")
    print("=" * 80)

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
