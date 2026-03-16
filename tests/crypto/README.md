# Crypto Module Tests

## Location

`src/crypto/*/tests.rs`

## Coverage

### Symmetric Encryption

| Algorithm | Tests | Source |
|-----------|-------|--------|
| AES-128 | 45 | `src/crypto/symmetric/aes/tests.rs` |
| AES-256-GCM | 32 | `src/crypto/symmetric/aes_gcm/tests.rs` |
| ChaCha20-Poly1305 | 28 | `src/crypto/symmetric/chacha20poly1305/tests.rs` |

### Hash Functions

| Algorithm | Tests | Source |
|-----------|-------|--------|
| SHA-256 | 12 | `src/crypto/hash/sha256/tests.rs` |
| SHA-512 | 12 | `src/crypto/hash/sha512/mod.rs` |
| SHA3-256 | 9 | `src/crypto/hash/sha3/mod.rs` |
| BLAKE3 | 22 | `src/crypto/hash/blake3/tests.rs` |

### Asymmetric Cryptography

| Algorithm | Tests | Source |
|-----------|-------|--------|
| Ed25519 | 35 | `src/crypto/asymmetric/ed25519/tests.rs` |
| X25519 | 28 | `src/crypto/asymmetric/curve25519/tests.rs` |
| P-256/ECDSA | 31 | `src/crypto/asymmetric/p256/tests.rs` |

### Zero-Knowledge Proofs

| System | Tests | Source |
|--------|-------|--------|
| Groth16 | 42 | `src/crypto/zk/groth16/tests.rs` |
| Halo2 | 38 | `src/crypto/zk/halo2/tests.rs` |

## Test Vectors

All tests use standardized vectors:

- AES: NIST FIPS 197
- AES-GCM: NIST SP 800-38D
- ChaCha20-Poly1305: RFC 8439
- SHA-2: NIST FIPS 180-4
- SHA-3: NIST FIPS 202
- Ed25519: RFC 8032
- X25519: RFC 7748

## Running

```bash
cargo test --lib --features std crypto::
```
