# NONOS Attestation Circuit (Groth16, BLS12-381)

Aattestation circuit and host utilities for embedding verifiable measurements into the NØN·OS boot trust chain. This package produces and validates arkworks Groth16 verifying keys (VKs) in canonical compressed form, ready to embed into the bootloader via the provisioning toolchain.

Status: Real artifacts only (ProvingKey/VerifyingKey). Single‑party “generate” exists for controlled environments; for future additions we use a proper MPC/trusted ceremony externally and import the PK/VK here.

---

## Table of contents

- Overview
- Circuit semantics
- Security and design rationale
- Build and install
- CLI usage (commands and examples)
- Inputs/outputs and formats
- Provisioning workflow (with zk-embed)
- Embedding VKs in the bootloader registry
- Versioning and program identity
- Reproducibility and fingerprints
- Operational policy (MPC, storage, and reviews)
- Troubleshooting
- FAQ
- License

---

## Overview

This directory provides:
- A no_std circuit library defining the attestation statement over BLS12‑381.
- A std host binary for production‑safe key operations:
  - generate: circuit-specific setup (single party). Use only if policy allows; otherwise use your ceremony outputs.
  - extract-vk: extracts a VK from an arkworks ProvingKey (PK) and writes canonical‑compressed bytes.
  - inspect-vk: validates a VK and prints canonical length, fingerprint, and expected public inputs.

All outputs are arkworks CanonicalSerialize (compressed), the format enforced by the boot verifier.

---

## Circuit semantics

Public inputs (statement):
- capsule_commitment: 32 bytes
- program_hash: 32 bytes

Witnesses (private):
- pcr_preimage: 64 bytes (configurable in code; see PCR_PREIMAGE_LEN)
- hardware_attestation: u64 numeric level

Constraints (baseline, auditable):
1) program_hash equals a precomputed constant derived off‑circuit:
   - BLAKE3::derive_key("NONOS:ZK:PROGRAM:v1", program_id_bytes)
2) pcr_preimage is non‑trivial (not all zeros). Extend with a SHA‑256 gadget if your policy requires digest exposure on‑chain/off‑box.
3) hardware_attestation ≥ MIN_HW_LEVEL (default 0x1000).
4) capsule_commitment is present and not all zeros. Binding to manifest or public inputs is enforced by the boot policy at verification time.

Out of circuit:
- Signature verification remains in firmware (keeps proving semantics stable across signer changes).
- Boot policy chooses the commitment binding mode and enforces it (public inputs vs manifest).

---

## Security and design rationale

- Proving system: Groth16 over BLS12‑381 (arkworks).
- Domain separation:
  - Program hash DS: NONOS:ZK:PROGRAM:v1
- VK provenance: Treat verifying keys like code. Store canonical bytes, record fingerprints, and review under change control.
- Ceremony:
  - Recommended: MPC/trusted setup outside this repo; use “extract‑vk” to integrate the VK.
  - Allowed (controlled): single‑party “generate” with deterministic seed for repeatable builds in private environments.

---

## Build and install

From repository root (workspace member):
```
cargo build --release -p nonos-attestation-circuit
```

Just the CLI:
```
cargo build --release -p nonos-attestation-circuit --bin generate-keys
```

Artifacts: `target/release/generate-keys`

---

## CLI usage

The single binary provides production operations that work on arkworks PK/VK artifacts.

1) generate — Circuit-specific setup (single party)
- Use only if your policy allows single‑party setup. Otherwise, run your ceremony externally and import PK/VK.

Example:
```
cargo run --release -p nonos-attestation-circuit -- \
  generate --output out/attest --print-program-hash
```

Outputs:
- out/attest/attestation_proving_key.bin (arkworks CanonicalSerialize, compressed)
- out/attest/attestation_verifying_key.bin (arkworks CanonicalSerialize, compressed)
- Prints:
  - vk_blake3 fingerprint
  - public_inputs_expected = vk.ic.len() - 1
  - program_hash_hex (if requested)

2) extract-vk — Extract VK from PK (canonical compressed)
- Use this for ceremony outputs.

Example:
```
cargo run --release -p nonos-attestation-circuit -- \
  extract-vk --pk /path/to/ceremony_proving_key.bin --out out/attest/verifying_key.bin
```

3) inspect-vk — Validate VK and print metadata
- Confirms encoding and prints reproducible fingerprints.

Example:
```
cargo run --release -p nonos-attestation-circuit -- \
  inspect-vk --vk out/attest/verifying_key.bin
```

Printed metadata:
- canonical_compressed_len (bytes)
- vk_blake3 fingerprint
- public_inputs_expected

---

## Inputs/outputs and formats

Accepted inputs:
- ProvingKey/VerifyingKey in arkworks CanonicalSerialize
  - Compressed or uncompressed (tool will deserialize and re‑emit canonical compressed for outputs)

Outputs:
- VK: canonical compressed arkworks bytes (what firmware expects)
- PK: canonical compressed arkworks bytes (if generated here)

Fingerprints:
- Use BLAKE3 over canonical compressed VK bytes. Keep these in code review and release notes.

Public inputs count:
- Must equal vk.ic.len() − 1
- The boot verifier enforces this at runtime

---

## Provisioning workflow (with zk‑embed)

Once you have canonical compressed VK bytes:

1) Generate embed constants:
```
cargo run --release -p zk-embed -- \
  --program-id-str "zkmod-attestation-program-v1" \
  --vk out/attest/verifying_key.bin \
  --const-prefix ATTEST_V1 > vk_snippet.rs
```

2) Open vk_snippet.rs and copy:
- PROGRAM_HASH_ATTEST_V1: [u8; 32]
- VK_ATTEST_V1_BLS12_381_GROTH16: &[u8]

3) Paste constants into firmware at src/zk/registry.rs and add to ENTRIES:
```rust
static ENTRIES: &[(&[u8; 32], &[u8])] = &[
    (&PROGRAM_HASH_ATTEST_V1, VK_ATTEST_V1_BLS12_381_GROTH16),
];
```

4) Build firmware with ZK:
- Public inputs binding:
  ```
  cargo build --release --features zk-groth16,zk-vk-provisioned
  ```
- Manifest binding:
  ```
  cargo build --release --features zk-groth16,zk-vk-provisioned,zk-bind-manifest
  ```

Provisioning guard:
- The build fails intentionally if `zk-vk-provisioned` is set but no entries exist (prevents accidental ZK builds without VKs).

---

## Embedding VKs in the bootloader registry

- Location: `src/zk/registry.rs`
- Each entry pairs one PROGRAM_HASH with one VK byte slice.
- Constant‑time compare is used for program hash dispatch.
- Use unique, stable program IDs; never reuse a program ID for a modified circuit.

---

## Versioning and program identity

- PROGRAM_HASH = BLAKE3::derive_key("NONOS:ZK:PROGRAM:v1", program_id_bytes)
- Changing program_id changes PROGRAM_HASH. Keep program_id stable per circuit version.
- If circuit constraints change, define a new program_id and embed a new VK entry.

Recommended governance table (in repo docs):
- program_id
- program_hash (hex)
- vk_fingerprint (BLAKE3 of canonical VK)
- binding mode (public_inputs or manifest)
- status (active/deprecated/revoked)
- ceremony reference (hashes, dates, tool versions)

---

## Reproducibility and fingerprints

- Record the vk_blake3 fingerprint and the exact command used to produce constants.
- Capture arkworks crate versions, Rust toolchain version, and feature flags used.
- For single‑party generate (if used), pin or record the deterministic seed.

---

## Operational policy (MPC, storage, and reviews)

- Preferred: multi‑party ceremony (Powers of Tau / circuit‑specific MPC) with public transcripts where possible.
- Storage: PK is sensitive; store encrypted at rest, restrict access. VK is public; store canonical bytes in VCS with code review.
- Reviews: Treat VK changes like code changes; require reviewer sign‑off and fingerprint checks.

---

## Troubleshooting

- “not a valid arkworks VK/PK”:
  - Ensure the file is arkworks CanonicalSerialize (BLS12‑381 Groth16)
  - If unsure: `inspect-vk` or re‑emit via `extract-vk` or normalize with your ceremony tooling
- “public inputs mismatch” at runtime:
  - Ensure proof producer encodes exactly `vk.ic.len() − 1` 32‑byte big‑endian field elements
- “unknown program hash”:
  - The capsule used a program ID that doesn’t match the embedded PROGRAM_HASH. Align your program ID string and re‑run zk‑embed.

---

## FAQ

- Q: Why not verify signatures in the circuit?
  - A: Bootloader already verifies signatures; keeping signing out of circuit makes proofs independent of signer/curve changes and reduces proving cost.
- Q: Can I reuse the same program_id after a circuit tweak?
  - A: No. New circuit version → new program_id → new PROGRAM_HASH and VK entry.
- Q: Can I use BN254/Bn128 VKs?
  - A: No. This stack is Groth16 over BLS12‑381 only.

---

## License

- Library and tools in this directory: AGPL‑3.0
- Bootloader code: AGPL-3.0 (see repository LICENSE files)
