# NØNOS ZK Ceremony Toolkit

Offline tooling for running multi-party Powers-of-Tau ceremonies. This is not part of the bootloader runtime - it's used once (or rarely) to establish the cryptographic trusted setup that underlies NØNOS ZK attestation.

---

## Where this fits

The ceremony produces cryptographic parameters that eventually get embedded into the bootloader:

```
zk-ceremony (you are here)
    ↓ produces PoT transcripts
nonos-attestation-circuit
    ↓ generates PK/VK from transcripts
zk-embed
    ↓ converts VK to Rust code
bootloader
    → verifies proofs using embedded VK
```

The bootloader never sees `.ptau` files or ceremony scripts. It only uses the final verifying key bytes. This toolkit exists so that key generation can be done properly with multiple independent participants, auditable logs and no single point of trust.

---

## What's included

```
bin/
  init_powersoftau.sh      Create initial transcript
  contribute.sh            Add randomness contribution
  verify_chain.sh          Verify transcript chain
  prepare_phase2.sh        Prepare for circuit-specific setup
  create_signed_bundle.sh  Create signed VK bundle
  assemble_bundle.sh       Assemble t-of-n bundle
  inspect_bundle.sh        Inspect and verify bundle
Dockerfile                 Reproducible powersoftau build
RUNBOOK.md                 Step-by-step operator procedures
```

---

## Prerequisites

You'll need:
- `powersoftau` binary (build from the Dockerfile for reproducibility)
- `jq` for JSON processing
- `sha256sum` and `tar` for hashing and packaging
- HSM or KMS access for production signing

---

## Quick start (testing only)

Build the powersoftau container:
```
docker build -t nonos/powersoftau:latest .
```

Initialize a transcript:
```
./bin/init_powersoftau.sh --power 22 --operator "TestOrg" --out pot_0000.ptau
```

Contribute randomness:
```
./bin/contribute.sh --in pot_0000.ptau --out pot_0001.ptau --name "TestOrg:Alice" --entropy /dev/urandom
```

Prepare phase-2:
```
./bin/prepare_phase2.sh --tau pot_0001.ptau --out pot_phase2.ptau
```

This single-party flow is for testing. Real ceremonies need multiple independent participants contributing randomness - if even one participant is honest and destroys their toxic waste, the setup is secure.

---

## Ceremony

A ceremony looks like this:

1. Coordinator creates the initial transcript
2. Each participant, in sequence:
   - Downloads and verifies the previous transcript
   - Contributes their own randomness
   - Signs and publishes their contribution log
3. Auditors verify the full chain of contributions
4. Coordinator prepares the phase-2 transcript
5. Offline key generation produces proving key (secret) and verifying key
6. Release authority signs the VK bundle with threshold signatures
7. CI verifies the bundle and runs `zk-embed` to produce bootloader code

See `RUNBOOK.md` for detailed step-by-step procedures with checklists.

---

## Threshold signing

Production bundles should use t-of-n signing so no single party can forge a release:

```
./bin/assemble_bundle.sh \
  --vk verifying_key.bin \
  --meta metadata.json \
  --signers signers.json \
  --sigs-dir collected_signatures/ \
  --out attestation_bundle.tar.gz
```

The `signers.json` specifies who can sign and how many signatures are required:
```json
{
  "threshold": 3,
  "signers": [
    {"id": "alice", "pubkey_hex": "..."},
    {"id": "bob", "pubkey_hex": "..."},
    {"id": "carol", "pubkey_hex": "..."},
    {"id": "dave", "pubkey_hex": "..."}
  ]
}
```

With threshold 3 and 4 signers, any 3 can produce a valid bundle.

---

## Bundle contents

The final bundle is a tar.gz containing:

```
attestation_bundle.tar.gz
├── attestation_verifying_key.bin   Canonical compressed VK
├── metadata.json                   Provenance, hashes, versions
├── signers.json                    Threshold configuration
└── signatures/
    ├── alice.sig
    ├── bob.sig
    └── carol.sig
```

---

## Provenance and auditing

Every script emits JSON logs recording:
- SHA256 hashes of input and output transcripts
- Tool versions and binary hashes
- Operator identities
- Timestamps
- Host fingerprints (hashed by default for privacy)

These logs should be signed by each participant and archived in immutable storage. For production releases, engage a third-party cryptographic auditor to verify the transcript chain.

---

## Security notes

- Proving keys are secret. Store them in protected, access-controlled storage.
- Use HSM or KMS for production signing. Local key files are for development only.
- Archive everything. Transcripts, logs, signatures - all of it goes to immutable storage.
- Verify before you build. Never use a transcript without checking the chain.

---

## Arweave

Bundles can be uploaded to Arweave for permanent, tamper-evident storage:

```
./bin/assemble_bundle.sh ... --arweave-key wallet.json
```

The bundle gets repackaged with an `arweave.json` file containing the transaction ID.

---

## References

- Powers-of-Tau concept: https://github.com/zkcrypto/powersoftau
- arkworks (Rust ZK library): https://arkworks.rs/
- Groth16 paper: https://eprint.iacr.org/2016/260

---

## License

AGPL-3.0
