---
applyTo: "src/crypto/**,src/zk_engine/**,src/vault/**"
---

# Cryptographic Engineering — NONOS Kernel

## Cardinal Rules

1. **Never implement a primitive from scratch.** Wrap audited implementations. If no audited implementation exists for `no_std`, port one with exact algorithmic fidelity.
2. **Constant-time everything.** All secret-dependent operations use `subtle::ConstantTimeEq` / `subtle::ConditionallySelectable`. No branching, no indexing, no early-return on secret data.
3. **Zeroize after use.** Every key, nonce, seed, and intermediate secret is zeroed with `core::ptr::write_volatile` + compiler fence before the buffer is freed or goes out of scope.
4. **No `f32`/`f64`.** Target has no x87/AVX. All field arithmetic uses integer operations only.

## Primitive Inventory

### Symmetric

| Algorithm | Location | Notes |
|-----------|----------|-------|
| AES-128/256 | `crypto/aes/` | ECB/CBC/CTR/GCM modes |
| ChaCha20-Poly1305 | `crypto/chacha/` | IETF variant (96-bit nonce) |
| AES-GCM | `crypto/aes/gcm.rs` | Used by CryptoFS and TLS |

### Asymmetric

| Algorithm | Location | Notes |
|-----------|----------|-------|
| Ed25519 | `crypto/ed25519/` | Kernel signature verification, capability tokens |
| Curve25519 | `crypto/curve25519/` | Key exchange (X25519) |
| secp256k1 | `crypto/secp256k1/` | Blockchain/capsule signatures |
| P-256 | `crypto/p256/` | TLS compatibility |
| RSA | `crypto/rsa/` | Legacy verification only |

### Hash

| Algorithm | Location | Notes |
|-----------|----------|-------|
| SHA-256/512 | `crypto/sha2/` | General hashing, HMAC |
| SHA-3 (Keccak) | `crypto/sha3/` | Boot measurement |
| BLAKE3 | `crypto/blake3/` | Fast hashing, Merkle trees |
| SHA-1 | `crypto/sha1/` | **Legacy only** — behind `sha1-legacy` feature |

### Post-Quantum

| Algorithm | Location | Build |
|-----------|----------|-------|
| ML-KEM (Kyber) | `crypto/kyber/` | PQClean C compiled in `build.rs` |
| ML-DSA (Dilithium) | `crypto/dilithium/` | Feature-gated |
| SPHINCS+ | `crypto/sphincs/` | Hash-based signatures |

### Zero-Knowledge

| System | Location | Purpose |
|--------|----------|---------|
| Groth16 | `zk_engine/groth16/` | Boot attestation proofs |
| Halo2 (KZG) | `zk_engine/halo2/` | Recursive proofs |
| PLONK | `zk_engine/plonk/` | General circuits |

## Constant-Time Patterns

```rust
use subtle::{ConstantTimeEq, ConditionallySelectable, Choice};

// ✅ CORRECT — constant-time comparison
let is_valid: Choice = computed_mac.ct_eq(&expected_mac);
if is_valid.into() {
    // proceed
}

// ❌ WRONG — timing side-channel
if computed_mac == expected_mac {
    // proceed — attacker can measure branch timing
}

// ✅ CORRECT — constant-time selection
let result = u64::conditional_select(&value_if_false, &value_if_true, condition);

// ❌ WRONG — branching on secret
let result = if secret_bit { value_a } else { value_b };
```

## Zeroization Pattern

```rust
fn sign_message(key: &[u8; 32], msg: &[u8]) -> Result<[u8; 64], CryptoError> {
    let mut expanded_key = [0u8; 64];
    expand_key(key, &mut expanded_key)?;

    let signature = compute_signature(&expanded_key, msg)?;

    // MUST zeroize before returning
    // SAFETY: volatile write prevents compiler from optimizing away the zeroing
    unsafe {
        core::ptr::write_volatile(&mut expanded_key as *mut [u8; 64], [0u8; 64]);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    Ok(signature)
}
```

## AEAD Usage (TLS, CryptoFS)

```rust
// Nonce management is CRITICAL:
// - Never reuse a nonce with the same key
// - Counter-based nonces: increment atomically
// - Random nonces: must be 96+ bits from CSPRNG

let mut nonce_counter: u64 = 0;

fn encrypt_record(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let nonce = build_nonce(nonce_counter);
    nonce_counter += 1; // Monotonic — never wraps (check!)

    aes_gcm_encrypt(key, &nonce, plaintext, &[]) // AAD empty or include header
}
```

**Nonce reuse = catastrophic key recovery.** If a nonce might repeat, the protocol is broken.

## Key Hierarchy

```
Root Key (Ed25519 seed in TPM / .keys/dev-signing.seed)
├── Kernel signing key (Ed25519)
├── Capability signing key (derived)
├── CryptoFS master key (derived via HKDF)
│   └── Per-file keys (derived via HKDF + file ID)
└── TLS ephemeral keys (Curve25519/P-256, per-session)
```

Keys are derived via HKDF-SHA256. Never use a root key directly for encryption.

## Error Handling in Crypto

Crypto errors must be **constant-time** and **opaque to callers**:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    InvalidSignature,     // Don't say WHY it's invalid
    DecryptionFailed,     // Don't leak which byte failed
    InvalidKeyLength,
    NonceExhausted,
    EntropyInsufficient,
}
```

Never return error messages that leak internal state (which byte mismatched, which step failed in verification).

## PQClean Integration

Post-quantum crypto uses C code from PQClean, compiled in `build.rs`:

```rust
// build.rs compiles:
//   third_party/pqclean/crypto_kem/kyber768/clean/*.c
//   → linked as static library

// Rust FFI wrapper in crypto/kyber/:
extern "C" {
    fn PQCLEAN_KYBER768_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> i32;
    fn PQCLEAN_KYBER768_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> i32;
    fn PQCLEAN_KYBER768_CLEAN_crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;
}
```

Always zeroize the secret key after use. The C code does not do this for you.

## Testing Crypto

- Test vectors from NIST/RFC are mandatory for every primitive
- Run on host: `cargo test --features std` (enables `rand` for randomized tests)
- Test constant-time property: verify the function doesn't short-circuit on first mismatch
- Fuzzing: feed random garbage to all parser/decoder paths

## Anti-Patterns

- **No `==` on secrets** — use `ct_eq()` from `subtle`
- **No `if secret_byte { ... }`** — use `ConditionallySelectable`
- **No `println!` of key material** — even in debug builds
- **No reusing nonces** — counter or random, never repeat
- **No forgetting to zeroize** — wrap in a struct with `Drop` if needed
- **No SHA-1 for security** — only for legacy protocol compat behind feature gate
