# Trusted Setup & Key Ceremony

Documentation for auditors and ceremony participants.

---

## How Groth16 Setup Works

Groth16 requires a per-circuit trusted setup. The setup produces:
- **Proving key** (~979KB): Used to generate proofs
- **Verifying key** (584 bytes): Used to verify proofs

The setup process also produces "toxic waste" random values that, if known, allow forging proofs. These must be destroyed.

---

## Single-Party Setup

For development or single-organization deployments:

```bash
make generate-zk-keys
```

This runs `generate-keys` with the seed from `ZK_KEY_SEED` in the Makefile.

Current production seed: `nonos-production-attestation-v1-2026`

The seed makes key generation deterministic and reproducible. Same seed = same keys.

### Key Locations

| File | Size | Purpose |
|------|------|---------|
| `generated_keys/attestation_proving_key.bin` | ~979KB | Proof generation |
| `generated_keys/attestation_verifying_key.bin` | 584 bytes | Proof verification |

### Embedding VK

```bash
make show-vk
```

Copy the output to `nonos-boot/src/zk/registry/keys.rs`:
- `VK_BOOT_AUTHORITY_BLS12_381_GROTH16`: Raw VK bytes
- `VK_FINGERPRINT_BOOT_AUTHORITY`: BLAKE3 fingerprint

---

## Multi-Party Ceremony

For high-security deployments where no single party should be trusted:

### Protocol

1. **Participant 1** runs setup with their randomness
2. **Participant 2** takes that output, adds their randomness, outputs new keys
3. Repeat for N participants
4. Final output is the proving and verifying keys
5. **Everyone destroys their local randomness**

Security property: As long as ONE participant is honest and destroys their randomness, the toxic waste is unrecoverable.

### Ceremony Mode

The tool supports ceremony mode:

```bash
./generate-keys --ceremony-dir ./ceremony --participant-id "alice@example.com"
```

### Metadata Tracking

`metadata.json` in the ceremony directory tracks:

```json
{
  "circuit_name": "nonos-attestation",
  "version": "1.0.0",
  "created_at": "2026-01-15T10:00:00Z",
  "contributors": [
    {
      "id": "alice@example.com",
      "timestamp": "2026-01-15T10:00:00Z",
      "contribution_hash": "0x..."
    },
    {
      "id": "bob@example.com",
      "timestamp": "2026-01-15T11:00:00Z",
      "contribution_hash": "0x..."
    }
  ]
}
```

---

## VK Fingerprint Computation

The verifying key fingerprint provides integrity verification:

```rust
let fingerprint = blake3::Hasher::new_derive_key("NONOS:VK:FINGERPRINT:v1")
    .update(&vk_bytes)
    .finalize();
```

Current production fingerprint:
```
0dfe cffb bc4c f00a 9777 1ca2 eb3a dd4a
5c5a fba5 fa5b 1f26 2436 b5ce 73d2 7228
```

---

## Key Versioning

Keys have version numbers:

```rust
if version < self.minimum_version {
    return KeyStatus::VersionTooOld;
}
```

- Minimum version can be bumped (never lowered)
- Old keys are phased out without explicit revocation

---

## Revocation

```rust
pub struct RevocationEntry {
    pub key_id: KeyId,
    pub revoked_at: u64,
    pub reason: RevocationReason,
}

pub enum RevocationReason {
    Compromised,
    Superseded,
    PolicyChange,
    Unknown,
}
```

Currently local to each bootloader instance. Production deployment needs secure update mechanism for revocation distribution.

---

## Circuit update procedure

Changing the circuit requires a new trusted setup:

1. Modify circuit code
2. Run new trusted setup (single-party or ceremony)
3. Get new proving key and verifying key
4. Update `keys.rs` with new VK bytes and fingerprint
5. Rebuild bootloader
6. Re-prove all kernels with new proving key

Old bootloaders cannot verify proofs from new circuits. This is intentional.

---

## Security Checklist for Ceremony

### Before Ceremony

- [ ] Verify circuit code hasn't been tampered with
- [ ] All participants have verified the circuit source
- [ ] Ceremony software is built from verified source
- [ ] Communication channel is authenticated (participants verify each other)

### During Ceremony

- [ ] Each participant generates fresh randomness
- [ ] Each participant verifies they received valid input from previous participant
- [ ] Each participant publishes their contribution hash
- [ ] No participant reveals their randomness

### After Ceremony

- [ ] All participants destroy their local randomness
- [ ] Final keys are verified to be valid
- [ ] VK is embedded in bootloader
- [ ] Proving key is secured appropriately

---

## Threat Model for Ceremony

### Attacker Goals

Recover toxic waste to forge proofs.

### Attack Vectors

1. **Compromise all participants**: If all N participants are compromised, attacker gets toxic waste
2. **Compromise ceremony software**: Malicious software could leak randomness
3. **Side channels during ceremony**: Timing, power analysis, etc.
4. **Social engineering**: Convince participants to reveal randomness

### Mitigations

- **More participants**: Attacker must compromise ALL of them
- **Diverse participants**: Different organizations, jurisdictions, motivations
- **Air-gapped machines**: No network during randomness generation
- **Verified software**: Build from source, verify hashes
- **Public commitments**: Participants publish hashes before revealing contributions

---

## Recovery from Compromise

If toxic waste is recovered:

1. **Immediate**: Stop accepting proofs from compromised circuit
2. **Short-term**: Run new ceremony with more/different participants
3. **Medium-term**: Update all bootloaders with new VK
4. **Long-term**: Re-sign and re-prove all kernels

Defense in depth: Even with forged proofs, attacker still needs signing key.

---

## Audit trail

For production deployments, maintain:

1. **Ceremony transcript**: All communications, contribution hashes
2. **Participant attestations**: Signed statements that randomness was destroyed
3. **VK provenance**: Chain from ceremony to bootloader binary
4. **Key rotation history**: When and why keys were rotated

---

## Threshold-Signing (current state)

Partially implemented. Multiple keys generated with threshold parameter.

**Current**: Multi-sig. If threshold is 3, need 3 separate signatures from 3 different full keys.

**Not implemented**: Proper threshold Ed25519 (FROST) where partial signatures combine cryptographically. 
