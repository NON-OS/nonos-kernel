# Bootloader Dedup Plan — Live-Path Call-Graph Adjudication (Task 3 / W2)

Scope: `nonos-bootloader/` (crate `nonos_boot`). Read-only audit. No `.rs` modified.
Method: call graph from the real entry point, not directory names. A `pub mod`
declaration is not evidence of liveness; only a resolved call site is.

## The Real Entry Point and Live Orchestration Path

The original task brief's `boot/main/` and `boot/init.rs` do not exist. The real
root is the binary crate's `entry/` module (declared only in `main.rs`, never in
`lib.rs`), which drives the library crate's `boot/` orchestration layer.

Verbatim live spine (each hop a resolved call site):

```
main.rs:28          efi_main -> entry::boot_entry
entry/boot.rs:24    boot_entry
  :25  init_boot_services            (entry/init.rs:19)
  :26  run_uefi_init                 (nonos_boot::boot::uefi)
  :28  dev_override                  (entry/dev.rs)
  :29  select_security_mode          (entry/mode.rs:21 -> entry/action.rs:22)
  :33  run_security_checks           (boot/security/run.rs:30)
  :34  initialize_zk_replay_protection (boot/zk_init/init.rs)
  :35  run_hardware_discovery        (boot/hardware.rs)
  :36  run_verified_boot             (entry/pipeline.rs:28)
entry/pipeline.rs:34  run_kernel_load           (boot/kernel)
              :36  run_crypto_verification   (boot/crypto/run.rs:30)
              :37  run_zk_attestation        (boot/attestation/run/orchestrate.rs:26)
              :46  run_elf_parse             (boot/elf)
              :47  commit_rollback           (boot/crypto/rollback.rs)
              :49  run_handoff_prepare       (boot/prepare/run.rs)
```

`entry/` (294 LOC) is the binary's thin driver; `boot/` (≈2.4k LOC across 12
subtrees) is the library's orchestration. `entry/` imports `nonos_boot::boot::*`
(11 sites) and contains no parallel orchestration logic. This is bin→lib
**layering**, not duplication. The original brief's expected `boot/main/` was
superseded by `entry/`; `entry/` is the single live orchestrator. Verdict: both
KEEP (layered, single owner each).

The canonical kernel-trust chain (used to adjudicate keystore / verify):

```
pipeline.rs:36  run_crypto_verification
boot/crypto/run.rs:30  -> compute_hash (boot/crypto/hash.rs)
boot/crypto/hash.rs:21  use crate::kernel_verify::{verify_kernel_crypto,...}
boot/crypto/hash.rs:30  verify_kernel_crypto(data, st)
kernel_verify/signature.rs:20  use crate::crypto::sig::verify_signature_bytes
kernel_verify/signature.rs:43  verify_signature_bytes(kernel_code, signature)
crypto/sig.rs (facade)  pub use super::verify::verify_signature_bytes
crypto/verify/bytes.rs:19  use crate::crypto::keys::{... KEYSTORE}
crypto/verify/bytes.rs:28  KEYSTORE.lock()  <-- the trust root
```

`crypto/sig.rs` is a pure re-export facade: `pub use super::keys::{...}` /
`pub use super::verify::{...}`. The trust-anchoring static is
`crate::crypto::keys::KEYSTORE`.

---

## Group 1 — Keystores (the "three keystores" question)

| tree | live path + evidence (path:line) | verdict | recommendation | LOC delta | migration risk |
|---|---|---|---|---|---|
| `crypto/keys/` | `crypto/verify/bytes.rs:19,28` consumes `crate::crypto::keys::KEYSTORE`; reached from `kernel_verify/signature.rs:43` ← live `run_crypto_verification`. Also `crypto/sig.rs` re-exports it; `security/init/subsystem/keys.rs:26 init_production_keys()` populates it on live `run_security_checks`. | **LIVE — canonical** | **KEEP** | 0 (427 LOC kept) | n/a |
| `crypto/keyring/` | Only crate-wide reference is `crypto/mod.rs:17 pub mod keyring;`. Zero `use`, zero call, not in `crypto/sig.rs` facade. | **DEAD** | **DELETE** | −395 | none — no live caller; delete module + `crypto/mod.rs:17` |
| `crypto/keystore_v2/` | `init_production_keystore()` (api.rs:26, the only populate path) has **zero callers** — `KEYSTORE_V2` is never filled. `verify_multisig`/`verify_single` have zero external callers. Live touchpoints contribute nothing to trust: `get_keystore_fingerprint()` → constant string logged at `security/init/subsystem/keys.rs:37`; `wipe_all_keys()` at `handoff/exit/cleanup.rs:29` wipes an empty store. | **PARALLEL (never populated)** | **DELETE** (migrate 2 cosmetic call sites) | −424 (less ~6 lines re-added for fingerprint const) | low: replace `get_keystore_fingerprint()` source with the `crypto/keys` build constant; drop the no-op `wipe_all_keys()` call in `handoff/exit/cleanup.rs:29` (real wipe is the adjacent `crypto::sig::wipe_signing_state()` at :37). |

Resolution — exactly ONE keystore: **`crypto/keys/`**. Rationale (mechanism +
cite, not taste): it is the only store the live Ed25519 verification reads
(`crypto/verify/bytes.rs:28 KEYSTORE.lock()`) and the only store the live boot
populates (`init_production_keys()` via `security/init/subsystem/keys.rs:26`).
`keyring/` is unreferenced. `keystore_v2/` is a complete parallel trust store
(its own multisig verifier, its own `KeystoreV2`) that the boot never loads —
this is duplication, not defense in depth: defense in depth would require both
stores to gate the same decision; here only one is consulted and the other is
empty.

simplify discipline: all three are *parallel implementations of one
responsibility* (hold trusted pubkeys + validate). Only `crypto/keys` is wired.
The other two will drift (already do: `keystore_v2` carries a multisig API
`crypto/keys` lacks). Merge target = `crypto/keys`; delete the other two.

Severity (trust risk, for downstream register): **S2**, trending S1.
`keystore_v2` exposes a fully-formed `verify_multisig` against a store that is
always empty. Any future change that routes verification through it (a plausible
mistake — it is `pub` and named like the "v2" successor) would accept/reject on
an empty key set. A dead-but-wireable parallel verifier is a trust-bypass
latent, not mere cleanliness.

---

## Group 2 — Kernel Verification

| tree | live path + evidence (path:line) | verdict | recommendation | LOC delta | migration risk |
|---|---|---|---|---|---|
| `kernel_verify/` | `boot/crypto/hash.rs:21,30` `verify_kernel_crypto` ← live `run_crypto_verification` (pipeline.rs:36). | **LIVE — canonical** | **KEEP** | 0 (541 LOC) | n/a |
| `verify/` | Only `crate::verify::` references are internal (`verify/verify.rs:21`, `verify/loader.rs:18`); sole external mention is `loader/CONTRIBUTING.md:8` (doc, not code). No live `.rs` calls `validate_capsule`/`load_validated_capsule`. Note: its `mod.rs:21` merely re-exports `crypto::sig`, shadowing the canonical path. | **DEAD (parallel)** | **DELETE** | −360 | none — no live caller. Remove `pub mod verify;` (lib.rs:40). |
| `security/verify/` | Zero `security::verify` consumers crate-wide. `verify_kernel_signature_advanced`/`verify_signature` uncalled. | **DEAD (parallel)** | **DELETE** | −106 | none — remove `mod verify;` from `security/mod.rs`. |

Single recommended verifier: **`kernel_verify/`**. `verify/` and
`security/verify/` are parallel kernel/capsule verifiers (`verify/` even
re-derives a capsule status type) that the boot pipeline never reaches —
duplication, not DiD (DiD would require the pipeline to run two independent
verifiers; it runs exactly one, `kernel_verify`). Severity **S2**: two unwired
parallel signature verifiers with their own `verify_signature` are
mis-wire-prone trust latents.

---

## Group 3 — TPM

| tree | live path + evidence (path:line) | verdict | recommendation | LOC delta | migration risk |
|---|---|---|---|---|---|
| `hardware/tpm/` | `boot/zk_init/machine.rs:19` `crate::hardware::tpm::get_tpm_ek_public` ← live `initialize_zk_replay_protection` (entry/boot.rs:34). Also `security/anti_rollback/nvram/{read,write}.rs:17` `nv_read`/`nv_write`. | **LIVE — canonical TPM driver** | **KEEP** | 0 (704 LOC) | n/a |
| `tpm/` | Every `crate::tpm::` reference is internal to `tpm/` itself (own `TmpDevice`/`TmpError` API — note the `Tmp` typo'd prefix). `pub mod tpm;` (lib.rs:31) but zero binary/entry/boot/security consumer. | **DEAD (parallel)** | **DELETE** | −934 | none — remove `pub mod tpm;` (lib.rs:31). |
| `security/hardware/tpm_detect/` | `security/hardware/capabilities/detect.rs:19` `detect_tpm_capabilities` ← `boot/security/hardware.rs:26 detect_hardware_capabilities` ← live `run_security_checks`. | **LIVE — complementary (capability probe)** | **KEEP** (see note) | 0 (139 LOC) | n/a |

Single recommended TPM stack: **`hardware/tpm/`** (the command/NV driver).
`tpm/` (934 LOC) is a complete parallel TPM 2.0 command stack, fully dead — the
single largest removable tree in the audit, and an S2 trust latent (a parallel,
typo-prefixed TPM driver invitable by mistake).

`security/hardware/tpm_detect/` is **kept as defense-in-depth-adjacent**: it is
a different responsibility (presence/capability *scoring* feeding the security
posture) than `hardware/tpm/`'s command driver, and it is on the live path via
`detect_hardware_capabilities`. Justification is mechanism, not taste: distinct
`pub fn detect_tpm_capabilities` consumed by `capabilities/detect.rs`, not a
second copy of the command FIFO. Minor concern (S4): it re-implements TPM-presence
probing that `hardware/tpm/state/detect.rs` also performs — a future consolidation
could have `tpm_detect` call into `hardware/tpm` rather than re-probe, but this is
cleanliness, not a trust risk; out of scope for delete.

---

## Group 4 — Attestation

| tree | live path + evidence (path:line) | verdict | recommendation | LOC delta | migration risk |
|---|---|---|---|---|---|
| `boot/attestation/` | `entry/pipeline.rs:37` `run_zk_attestation`; `attestation/run/orchestrate.rs:21` `crate::zk::{verify_boot_attestation,has_zk_proof}`. | **LIVE — ZK-attestation orchestrator** | **KEEP** | 0 (356 LOC) | n/a |
| `security/attestation/` | `init_attestation` (api/state.rs:22) ← `crate::security::init_attestation` ← `boot/security/platform.rs:20,33` (live `run_security_checks`); `generate_attestation_quote` (api/quote_gen.rs:20) ← `boot/prepare/attestation.rs:19` ← live `run_handoff_prepare`; `set_kernel_measurement` ← `boot/crypto/hash.rs:22`. | **LIVE — PCR/quote measurement engine** | **KEEP (DiD)** | 0 (680 LOC) | n/a |
| `zk/attest/` | `zk/mod.rs:44` re-exports `attest::{verify_boot_attestation,has_zk_proof,parse_zk_proof,...}`, consumed by live `boot/attestation/`. `zk::attest::types::ZkProofBlock` at `boot/attestation/binding.rs:18`. | **LIVE — ZK proof engine** | **KEEP** | 0 (575 LOC) | n/a |

All three LIVE and **distinct mechanisms** (not duplication): `zk/attest/`
produces/verifies the ZK boot proof; `boot/attestation/` orchestrates+enforces
it in the pipeline; `security/attestation/` is the TPM-PCR measurement & quote
subsystem. They gate *different* trust facts (ZK proof binding vs PCR
measurement) and run in series on the live path — this is genuine defense in
depth. KEEP all; no canonical collapse.

---

## Group 5 — ZK Init / ZK Core

| tree | live path + evidence (path:line) | verdict | recommendation | LOC delta | migration risk |
|---|---|---|---|---|---|
| `zk/` | `zk/mod.rs` re-exports consumed live: `verify_boot_attestation`/`has_zk_proof`/`parse_zk_proof` (boot/attestation), `init_machine_id`/`init_boot_nonce`/`is_*_initialized` (boot/zk_init), `zk::binding` (attestation/enforce/binding.rs:19). | **LIVE — canonical ZK engine** | **KEEP** | 0 (2799 LOC) | n/a |
| `boot/zk_init/` | `entry/boot.rs:34` `initialize_zk_replay_protection`; `boot/zk_init/{machine,nonce}.rs:19-21` only wrap `crate::zk::init_machine_id`/`init_boot_nonce` + `crate::hardware::tpm::get_tpm_ek_public`. | **LIVE — thin orchestration shim** | **KEEP (layered)** | 0 (153 LOC) | n/a |

Single recommended ZK choice: **`zk/`** is the engine; **`boot/zk_init/`** is its
153-LOC pipeline adapter (no crypto of its own — pure delegation to
`crate::zk`). Layering, not duplication; keep both.

---

## Summary

Single canonical choices (resolved by call site, not name):

- Keystore → **`crypto/keys/`** (the only store the live verifier reads and the
  live boot populates).
- Kernel verify → **`kernel_verify/`**.
- TPM driver → **`hardware/tpm/`** (with `security/hardware/tpm_detect/` kept as
  the complementary capability probe).
- Attestation → no single winner: `zk/attest/` + `boot/attestation/` +
  `security/attestation/` are three distinct, in-series trust mechanisms (DiD).
- ZK → **`zk/`** engine with **`boot/zk_init/`** as its thin live adapter.
- Orchestration → **`entry/`** (bin driver) over **`boot/`** (lib), layered.

Removable dead/parallel trees (real `wc -l`):

| tree | LOC | verdict | severity |
|---|---:|---|---|
| `tpm/` | 934 | DEAD parallel TPM stack | S2 |
| `crypto/keystore_v2/` | 424 (≈418 net) | PARALLEL, never populated | S2→S1 |
| `crypto/keyring/` | 395 | DEAD, only `pub mod` decl | S2 |
| `verify/` | 360 | DEAD parallel capsule/kernel verifier | S2 |
| `security/verify/` | 106 | DEAD parallel signature verifier | S2 |

- **Total LOC removable: ≈2,213** (2,219 minus ~6 lines re-added for the keystore
  fingerprint constant when collapsing `keystore_v2`).
- **Modules collapsible: 5 trees → 0** (delete `tpm/`, `crypto/keyring/`,
  `verify/`, `security/verify/`; absorb the 2 cosmetic `keystore_v2` call sites
  into `crypto/keys`). Plus `lib.rs` loses `pub mod tpm;`/`pub mod verify;` and
  `crypto/mod.rs`/`security/mod.rs` lose their dead `mod` lines.
- **Migration risk: low overall.** Four of five deletions have zero live callers
  (pure module removal). The only code change is `keystore_v2`: two cosmetic
  sites (`security/init/subsystem/keys.rs:37` fingerprint log;
  `handoff/exit/cleanup.rs:29` no-op wipe) — neither affects a trust decision.

Trust-risk note (for the downstream finding register): the parallel trust trees
(`keystore_v2` with a live-looking `verify_multisig` against an always-empty
store; `tpm/`, `verify/`, `security/verify/` as `pub` mis-wireable verifiers) are
**S2 trending S1** — not cleanliness. They are dead today but wireable by a
plausible future edit, at which point they would silently weaken or bypass the
trust chain. Execution of these deletions is deferred to Task 8 and user
approval; this document is recommendation-only.

## UNVERIFIED

None. Every verdict rests on a resolved call site or a cited absence (no
trait-object / fn-pointer / unresolved-cfg dispatch was encountered on the live
path; `dev_override` is `cfg(feature="dev-mode")` but both arms were read and it
does not affect any candidate-tree liveness).
