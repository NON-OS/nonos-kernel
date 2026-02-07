# Technical Reference

Deep dive into the nonos-bootloader cryptographic core.

---

## Cryptographic Primitives

| Primitive | Library | Purpose |
|-----------|---------|---------|
| Ed25519 | ed25519-dalek | Kernel signature |
| BLAKE3 | blake3 | Integrity hashing, key derivation, commitments |
| Groth16 | arkworks | ZK attestation proofs |
| BLS12-381 | arkworks | Pairing-friendly curve for Groth16 |

---

## Circuit Specification

### Size

- ~2,000-3,000 R1CS constraints
- Proving key: ~979KB (compressed arkworks format)
- Verifying key: 584 bytes
- Proof size: 192 bytes (constant)

### Public Inputs

Two 32-byte values:

**Program hash:**
```
BLAKE3_derive_key("NONOS:ZK:PROGRAM:v1", "zkmod-attestation-program-v1")
```
Identifies which circuit made the proof. Fixed at circuit setup time.

**Capsule commitment:**
```
BLAKE3_derive_key("NONOS:CAPSULE:COMMITMENT:v1", program_hash || pcr_preimage)
```
Binds the proof to its context.

### Private Inputs (Witnesses)

**PCR preimage**: 64 bytes. Hardware measurement data. Circuit proves it's non-zero without revealing it.

**Hardware attestation level**: 64-bit integer. Circuit proves it exceeds minimum threshold (0x1000).

### Constraints

1. `program_hash == expected_program_hash` (equality check)
2. `sum(pcr_preimage_bytes) > 0` (entropy check)
3. `hardware_attestation >= MIN_HW_LEVEL` (threshold check)
4. `capsule_commitment != 0` (non-zero check)

No heavy cryptography inside the circuit. All hashing happens outside.

---

## VK Fingerprint

The verifying key fingerprint is computed as:

```rust
BLAKE3::new_derive_key("NONOS:VK:FINGERPRINT:v1")
    .update(&vk_bytes)
    .finalize()
```

This is embedded in the bootloader alongside the VK for integrity verification.

Current production fingerprint:
```
0x0dfe cffb bc4c f00a 9777 1ca2 eb3a dd4a
0x5c5a fba5 fa5b 1f26 2436 b5ce 73d2 7228
```

---

## Boot Verification Stages

### Stage 6 - BLAKE3 Integrity

Compute hash of kernel binary. Quick sanity check that binary is intact.

### Stage 7 - Ed25519 Signature

Verify signature over kernel hash. Proves kernel was signed by trusted key holder.

### Stage 8 - ZK Verification

Verify Groth16 proof. Proves attestation constraints were satisfied.

**These are not redundant:**
- BLAKE3 alone: anyone can compute a hash
- Ed25519 alone: proves authorization, not attestation
- ZK alone: proves attestation, doesn't bind to specific binary
- All three: integrity + authorization + attestation

---

## Proof Block Format

Embedded at kernel offset (end - 272 bytes):

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic: `ZKP1` (0x5A4B5031) |
| 4 | 4 | Version |
| 8 | 4 | Proof length |
| 12 | 4 | Public inputs length |
| 16 | 32 | Program hash |
| 48 | 32 | Capsule commitment |
| 80 | 192 | Groth16 proof (A, B, C points) |

---

## Key Versioning

```rust
if version < self.minimum_version {
    return KeyStatus::VersionTooOld;
}
```

Minimum version can be bumped at runtime (never lowered). Phases out old keys without explicit revocation.

---

## Key Revocation

```rust
pub struct RevocationEntry {
    pub key_id: KeyId,
    pub revoked_at: u64,
    pub reason: RevocationReason,
}
```

Call `revoke_key(key_id, reason, timestamp)` and that key is done. Currently local to each bootloader instance.

---

## Threshold Signing

Partially implemented. Multiple keys generated with threshold parameter, but yet no proper threshold Ed25519 (FROST) and is part of next area of focus.

Current: multi-sig. If threshold is 3, you need 3 separate signatures from 3 different full keys. Each signer signs independently.

---

## Constant-Time Operations

```rust
#[inline(never)]
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}
```

No early exit branches. `#[inline(never)]` discourages optimizer transformation.

Caveat: UEFI isn't a hardened environment. Branch predictors, caches, speculative execution can leak timing. Practical risk is low for bootloader context.

---

## Performance

| Operation | Time |
|-----------|------|
| Proof generation | 2-5 seconds (build time) |
| Proof verification | 15-30 milliseconds (boot time) |
| Signature verification | <1 millisecond |
| BLAKE3 hash (4MB kernel) | <10 milliseconds |

---

## Crypto Assumptions

**Groth16 soundness**: Can't forge proofs without valid witnesses. Rests on discrete log hardness in BLS12-381 groups.

**Trusted setup**: If toxic waste leaks, proofs can be forged.

**BLAKE3 collision resistance**: Commitments and hashes assume no collisions.

**Random oracle model**: Non-interactive proofs assume hash function behaves randomly.

---

## Why these choices?

### Why Groth16?

- Constant-size proofs (192 bytes)
- Fast verification (~20ms)
- Mature implementation (arkworks)
- Well-studied security

Alternatives:
- PLONK: Universal setup but bigger proofs, slower verification
- STARKs: No setup, post-quantum but huge proofs (tens of KB)
- Bulletproofs: No setup, but verification is linear in circuit size

### Why BLS12-381?

Pairing-friendly curve with ~128-bit security. BN254 is slightly faster but has ~100-bit security. We chose the safer option.

### Why Ed25519 + BLAKE3 + Groth16?

Each does something different:
- Ed25519: Signs the kernel binary
- BLAKE3: Integrity hashes, key derivation, commitments
- Groth16: ZK attestation proofs

No overlap. Compromise one, the others still provide protection.

---

## Post-Quantum Considerations

Current state:
- Ed25519: Broken by large quantum computers (~3000+ logical qubits)
- BLS12-381: Also broken by quantum
- BLAKE3: Already fine

Migration plan:
- Signatures: Dilithium or Falcon (NIST PQC standards)
- ZK proofs: STARKs (already post-quantum)

The architecture supports swapping modules. Proof block has a version field.
