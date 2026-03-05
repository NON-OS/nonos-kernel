# Ceremony Runbook

Step-by-step procedures for running a production multi-party Powers-of-Tau ceremony and preparing circuit-specific Groth16 setup for NØNOS attestation.

---

## Roles

| Role | Responsibility |
|------|---------------|
| Coordinator | Prepares initial transcript, orchestrates participant order |
| Participant | Verifies prior transcript, contributes randomness, records evidence |
| Auditor | Verifies contributions and final transcripts |
| Release Authority | Produces signed VK bundle using HSM/KMS |

---

## Prerequisites

- Pinned, audited `powersoftau` binary (build from Dockerfile with specific commit)
- `jq`, `tar`, `sha256sum`, `openssl` or HSM client tools
- Secure artifact store (immutable, access-controlled)
- Root public key for verifying signed bundles

---

## Phase 1: Universal Powers-of-Tau

### Step 1: Coordinator creates initial transcript

```bash
./bin/init_powersoftau.sh \
  --power 22 \
  --out pot_0000.ptau \
  --operator "Org:Coordinator"
```

Record and distribute:
- Transcript file: `pot_0000.ptau`
- JSON log with SHA256, tool version, operator, timestamp
- Publish both to artifact store

### Step 2: Participant contributions

Each participant (k=0,1,2,...) in sequence:

1. **Verify prior transcript**:
   ```bash
   powersoftau verify --input pot_000${k}.ptau
   ```

2. **Contribute randomness**:
   ```bash
   ./bin/contribute.sh \
     --in pot_000${k}.ptau \
     --out pot_000$((k+1)).ptau \
     --name "Org:ParticipantName" \
     --entropy /dev/random
   ```

3. **Sign and publish log**:
   - Sign JSON log with participant's HSM or endorsed signing method
   - Upload transcript and signed log to artifact store

Log must include:
- `participant`: Identity string
- `input_sha256`: Hash of input transcript
- `output_sha256`: Hash of output transcript
- `powersoftau_version`: Tool version
- `entropy_source`: Description
- `timestamp`: ISO 8601

### Step 3: Auditor verification

Collect all transcripts and logs, then verify:

```bash
./bin/verify_chain.sh \
  --root pot_0000.ptau \
  --chain pot_0001.ptau pot_0002.ptau pot_0003.ptau \
  --log-dir contrib_logs \
  --root-pubkey auditors_root.pub
```

Confirm:
- Every transcript is valid extension of previous
- Every log signature verifies
- Log hashes match actual transcripts

---

## Phase 2: Circuit-specific setup

### Step 1: Prepare phase-2 transcript

```bash
./bin/prepare_phase2.sh \
  --tau pot_final.ptau \
  --out pot_phase2.ptau
```

### Step 2: Generate circuit keys (offline)

In a controlled, isolated environment:

1. Use arkworks with `pot_phase2.ptau` to generate:
   - `proving_key.bin` (keep secret, never distribute)
   - `verifying_key.bin` (canonical compressed format)

2. Validate with test proofs:
   ```bash
   # Generate proof with known witness
   # Verify proof with generated VK
   ```

---

## Bundle creation and signing

### Step 1: Create metadata.json

```json
{
  "tool_versions": {
    "powersoftau": "1.0.0-abc1234",
    "arkworks": "0.4.0"
  },
  "participants": [
    {"name": "Org:Alice", "transcript_sha256": "..."},
    {"name": "Org:Bob", "transcript_sha256": "..."}
  ],
  "vk_blake3": "...",
  "canonical_vk_len": 580,
  "timestamp": "2026-02-08T00:00:00Z"
}
```

### Step 2: Collect t-of-n signatures

Each signer signs `vk_bytes || metadata.json`:
```bash
# Signer creates signature with their HSM
# Places signature in collected_signatures/signer_id.sig
```

### Step 3: Assemble bundle

```bash
./bin/assemble_bundle.sh \
  --vk verifying_key.bin \
  --meta metadata.json \
  --signers signers.json \
  --sigs-dir collected_signatures/ \
  --out attestation_bundle.tar.gz
```

### Step 4: Publish

- Place bundle in release artifacts (immutable store)
- Record `vk_blake3` in release notes
- Optionally upload to Arweave for permanent storage

---

## CI/CD integration

1. CI fetches signed bundle from artifact store
2. CI verifies bundle signatures against root public key
3. CI runs `zk-embed`:
   ```bash
   zk-embed \
     --bundle attestation_bundle.tar.gz \
     --root-pubkey release_root.pub \
     --program-id-str "zkmod-attestation-program-v1" \
     --const-prefix ATTEST_V1 \
     --out vk_snippet.rs
   ```
4. CI injects snippet into build tree
5. CI builds with `--features "zk-groth16 zk-vk-provisioned"`
6. `build.rs` enforces provenance marker presence

---

## Audit and retention

- Archive all transcripts, logs, signatures, and bundles in immutable storage
- Generate SBOM for all tools used
- Run `cargo-audit` on Rust dependencies
- Engage third-party cryptographic auditor for production ceremonies

---

## Emergency procedures

### Suspected key compromise

1. **Halt** all provisioning and builds using affected VK
2. **Publish** signed revocation notice
3. **Start** new ceremony following same audited procedures
4. **Rotate** signing keys
5. **Update** CI and release authority records

### Transcript corruption

1. Identify last known-good transcript
2. Resume ceremony from that point with remaining participants
3. Document incident in audit log

---

## Checklist: Pre-ceremony

- [ ] Pinned powersoftau commit audited and documented
- [ ] All participants have verified signing capabilities
- [ ] Artifact store configured and access-controlled
- [ ] Root public key distributed to CI and auditors
- [ ] Communication channel established with all participants

## Checklist: Post-ceremony

- [ ] All transcripts archived
- [ ] All contribution logs archived with signatures
- [ ] Chain verification passed
- [ ] Phase-2 prepared
- [ ] PK/VK generated and tested
- [ ] Bundle signed with threshold
- [ ] Bundle published to artifact store
- [ ] CI integration tested
- [ ] Release notes updated with vk_blake3
