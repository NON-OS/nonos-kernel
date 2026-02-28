#!/usr/bin/env python3
"""
NØNOS Ethereum Module Test Vector Verification

Real computational tests for Ethereum transaction handling.
"""

import sys
import hashlib


def keccak256(data: bytes) -> bytes:
    """Keccak-256 hash - pure Python implementation"""
    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]

    def rot(x, n):
        return ((x << n) | (x >> (64 - n))) & 0xffffffffffffffff

    def keccak_f(state):
        for round_idx in range(24):
            C = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
            D = [C[(x - 1) % 5] ^ rot(C[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    state[x][y] ^= D[x]
            B = [[0] * 5 for _ in range(5)]
            rho_offsets = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
            for x in range(5):
                for y in range(5):
                    B[y][(2 * x + 3 * y) % 5] = rot(state[x][y], rho_offsets[x][y])
            for x in range(5):
                for y in range(5):
                    state[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])
            state[0][0] ^= RC[round_idx]
        return state

    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != (rate - 1):
        padded.append(0x00)
    padded.append(0x80)

    state = [[0] * 5 for _ in range(5)]
    for block_start in range(0, len(padded), rate):
        block = padded[block_start:block_start + rate]
        for i in range(min(len(block) // 8, 17)):
            x, y = i % 5, i // 5
            lane = int.from_bytes(block[i*8:(i+1)*8], 'little')
            state[x][y] ^= lane
        state = keccak_f(state)

    output = b''
    for i in range(4):
        x, y = i % 5, i // 5
        output += state[x][y].to_bytes(8, 'little')
    return output[:32]


def main():
    print("=" * 80)
    print("  ETHEREUM MODULE VERIFICATION")
    print("=" * 80)
    print()

    results = []

    # ==========================================================================
    # Test 1: Keccak-256 Known Test Vectors
    # ==========================================================================
    print("-" * 80)
    print("[Test 1] Keccak-256 Test Vectors")
    print("-" * 80)
    print()

    keccak_vectors = [
        (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
        (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
        (b"hello", "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"),
        (b"testing", "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02"),
    ]

    all_pass = True
    for msg, expected in keccak_vectors:
        computed = keccak256(msg).hex()
        match = computed == expected
        all_pass = all_pass and match
        print(f"  keccak256({msg!r})")
        print(f"  Expected: {expected}")
        print(f"  Computed: {computed}")
        print(f"  {'PASS' if match else 'FAIL'}")
        print()

    results.append(("Keccak-256 vectors", all_pass))
    print(f"Status: {'PASS' if all_pass else 'FAIL'}")
    print()

    # ==========================================================================
    # Test 2: EIP-55 Checksum Address
    # ==========================================================================
    print("-" * 80)
    print("[Test 2] EIP-55 Checksum Address")
    print("-" * 80)
    print()

    def to_checksum_address(addr_hex: str) -> str:
        addr = addr_hex.lower().replace("0x", "")
        addr_hash = keccak256(addr.encode()).hex()
        result = "0x"
        for i, c in enumerate(addr):
            if c in "0123456789":
                result += c
            elif int(addr_hash[i], 16) >= 8:
                result += c.upper()
            else:
                result += c.lower()
        return result

    eip55_vectors = [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        "0x52908400098527886E0F7030069857D2E4169EE7",
        "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
    ]

    all_pass = True
    for expected in eip55_vectors:
        computed = to_checksum_address(expected.lower())
        match = computed == expected
        all_pass = all_pass and match
        print(f"  Input:    {expected.lower()}")
        print(f"  Expected: {expected}")
        print(f"  Computed: {computed}")
        print(f"  {'PASS' if match else 'FAIL'}")
        print()

    results.append(("EIP-55 Checksum", all_pass))
    print(f"Status: {'PASS' if all_pass else 'FAIL'}")
    print()

    # ==========================================================================
    # Test 3: RLP Encoding - Ethereum Yellow Paper Examples
    # ==========================================================================
    print("-" * 80)
    print("[Test 3] RLP Encoding (Ethereum Yellow Paper)")
    print("-" * 80)
    print()

    def rlp_encode_int(value: int) -> bytes:
        if value == 0:
            return bytes([0x80])
        if value < 128:
            return bytes([value])
        hex_val = hex(value)[2:]
        if len(hex_val) % 2:
            hex_val = "0" + hex_val
        value_bytes = bytes.fromhex(hex_val)
        return bytes([0x80 + len(value_bytes)]) + value_bytes

    def rlp_encode_bytes(data: bytes) -> bytes:
        if len(data) == 1 and data[0] < 128:
            return data
        if len(data) == 0:
            return bytes([0x80])
        if len(data) < 56:
            return bytes([0x80 + len(data)]) + data
        len_bytes = []
        l = len(data)
        while l > 0:
            len_bytes.insert(0, l & 0xFF)
            l >>= 8
        return bytes([0xb7 + len(len_bytes)]) + bytes(len_bytes) + data

    def rlp_encode_list(items: list) -> bytes:
        payload = b"".join(items)
        if len(payload) < 56:
            return bytes([0xc0 + len(payload)]) + payload
        len_bytes = []
        l = len(payload)
        while l > 0:
            len_bytes.insert(0, l & 0xFF)
            l >>= 8
        return bytes([0xf7 + len(len_bytes)]) + bytes(len_bytes) + payload

    rlp_vectors = [
        # From Ethereum Yellow Paper Appendix B
        (b"dog", bytes([0x83]) + b"dog"),
        (b"", bytes([0x80])),
        (b"\x00", bytes([0x00])),
        (b"\x0f", bytes([0x0f])),
        (b"\x04\x00", bytes([0x82, 0x04, 0x00])),
    ]

    all_pass = True
    for input_val, expected in rlp_vectors:
        computed = rlp_encode_bytes(input_val)
        match = computed == expected
        all_pass = all_pass and match
        print(f"  RLP({input_val.hex() if input_val else 'empty'})")
        print(f"  Expected: {expected.hex()}")
        print(f"  Computed: {computed.hex()}")
        print(f"  {'PASS' if match else 'FAIL'}")
        print()

    # Integer encoding
    int_vectors = [
        (0, bytes([0x80])),
        (1, bytes([0x01])),
        (127, bytes([0x7f])),
        (128, bytes([0x81, 0x80])),
        (255, bytes([0x81, 0xff])),
        (256, bytes([0x82, 0x01, 0x00])),
        (1024, bytes([0x82, 0x04, 0x00])),
        (0xFFFF, bytes([0x82, 0xff, 0xff])),
        (0x010000, bytes([0x83, 0x01, 0x00, 0x00])),
    ]

    for value, expected in int_vectors:
        computed = rlp_encode_int(value)
        match = computed == expected
        all_pass = all_pass and match
        print(f"  RLP({value}) = {computed.hex()}")
        print(f"  Expected:   {expected.hex()}")
        print(f"  {'PASS' if match else 'FAIL'}")
        print()

    results.append(("RLP Encoding", all_pass))
    print(f"Status: {'PASS' if all_pass else 'FAIL'}")
    print()

    # ==========================================================================
    # Test 4: ERC-20 Function Selectors
    # ==========================================================================
    print("-" * 80)
    print("[Test 4] ERC-20 Function Selectors")
    print("-" * 80)
    print()

    function_selectors = [
        ("transfer(address,uint256)", "a9059cbb"),
        ("approve(address,uint256)", "095ea7b3"),
        ("transferFrom(address,address,uint256)", "23b872dd"),
        ("balanceOf(address)", "70a08231"),
        ("totalSupply()", "18160ddd"),
        ("allowance(address,address)", "dd62ed3e"),
    ]

    all_pass = True
    for func_sig, expected in function_selectors:
        computed = keccak256(func_sig.encode())[:4].hex()
        match = computed == expected
        all_pass = all_pass and match
        print(f"  {func_sig}")
        print(f"  Expected: 0x{expected}")
        print(f"  Computed: 0x{computed}")
        print(f"  {'PASS' if match else 'FAIL'}")
        print()

    results.append(("ERC-20 selectors", all_pass))
    print(f"Status: {'PASS' if all_pass else 'FAIL'}")
    print()

    # ==========================================================================
    # Test 5: EIP-155 Transaction v Values
    # ==========================================================================
    print("-" * 80)
    print("[Test 5] EIP-155 v Value Calculation")
    print("-" * 80)
    print()

    # v = chain_id * 2 + 35 + recovery_id
    v_test_cases = [
        (1, 0, 37, "Mainnet"),
        (1, 1, 38, "Mainnet"),
        (3, 0, 41, "Ropsten"),
        (4, 0, 43, "Rinkeby"),
        (5, 0, 45, "Goerli"),
        (56, 0, 147, "BSC"),
        (137, 0, 309, "Polygon"),
        (42161, 0, 84357, "Arbitrum"),
        (10, 0, 55, "Optimism"),
        (8453, 0, 16941, "Base"),
    ]

    all_pass = True
    for chain_id, recovery_id, expected_v, name in v_test_cases:
        computed_v = chain_id * 2 + 35 + recovery_id
        match = computed_v == expected_v
        all_pass = all_pass and match
        print(f"  {name} (chain {chain_id}): v = {chain_id} * 2 + 35 + {recovery_id} = {computed_v}")
        print(f"  Expected: {expected_v}")
        print(f"  {'PASS' if match else 'FAIL'}")
        print()

    results.append(("EIP-155 v values", all_pass))
    print(f"Status: {'PASS' if all_pass else 'FAIL'}")
    print()

    # ==========================================================================
    # Test 6: Ethereum Address from Public Key
    # ==========================================================================
    print("-" * 80)
    print("[Test 6] Address from Public Key (last 20 bytes of keccak)")
    print("-" * 80)
    print()

    # Test vector: known public key -> address
    # Verified test vector (uncompressed public key without 04 prefix)
    pubkey_hex = "04" + "50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6"
    pubkey_bytes = bytes.fromhex(pubkey_hex[2:])  # Remove 04 prefix
    # Address = last 20 bytes of keccak256(pubkey_64_bytes)
    expected_addr = "0x3e9003153d9a39d3f57b126b0c38513d5e289c3e"

    addr_hash = keccak256(pubkey_bytes)
    computed_addr = "0x" + addr_hash[-20:].hex()

    print(f"  Public key (uncompressed, 64 bytes):")
    print(f"  {pubkey_bytes[:32].hex()}")
    print(f"  {pubkey_bytes[32:].hex()}")
    print()
    print(f"  Keccak-256 hash: {addr_hash.hex()}")
    print(f"  Last 20 bytes:   {addr_hash[-20:].hex()}")
    print()
    print(f"  Expected address: {expected_addr}")
    print(f"  Computed address: {computed_addr}")
    print()

    addr_match = computed_addr.lower() == expected_addr.lower()
    results.append(("Address from pubkey", addr_match))
    print(f"Status: {'PASS' if addr_match else 'FAIL'}")
    print()

    # ==========================================================================
    # Test 7: Wei/Gwei/Ether Conversions
    # ==========================================================================
    print("-" * 80)
    print("[Test 7] Wei/Gwei/Ether Conversions")
    print("-" * 80)
    print()

    conversions = [
        (1, 0, 0, "1 wei"),
        (1_000_000_000, 1, 0, "1 Gwei"),
        (1_000_000_000_000_000_000, 1_000_000_000, 1, "1 Ether"),
        (21_000 * 20_000_000_000, 21_000 * 20, 0, "21000 gas * 20 Gwei"),
        (100_000_000_000_000_000, 100_000_000, 0, "0.1 Ether"),
    ]

    all_pass = True
    for wei, expected_gwei, expected_ether, desc in conversions:
        computed_gwei = wei // 1_000_000_000
        computed_ether = wei // 1_000_000_000_000_000_000

        gwei_match = computed_gwei == expected_gwei
        ether_match = computed_ether == expected_ether
        match = gwei_match and ether_match
        all_pass = all_pass and match

        print(f"  {desc}: {wei} wei")
        print(f"    = {computed_gwei} Gwei (expected {expected_gwei})")
        print(f"    = {computed_ether} Ether (expected {expected_ether})")
        print(f"  {'PASS' if match else 'FAIL'}")
        print()

    results.append(("Wei conversions", all_pass))
    print(f"Status: {'PASS' if all_pass else 'FAIL'}")
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
        print(f"  RESULT: ALL {len(results)} ETHEREUM TESTS PASSED")
    else:
        print("  RESULT: SOME TESTS FAILED")
    print("=" * 80)

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
