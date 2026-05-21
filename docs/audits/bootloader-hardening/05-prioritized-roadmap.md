# Prioritized Hardening Roadmap (terminal deliverable, Task 8)

This is a **written plan**, not a backlog: ordered phases, each item carrying the
finding IDs it resolves, a concrete action, a verification check (how you would
prove it fixed), the dependency/ordering rationale, and what it unblocks. Source
of truth for every finding is `01-findings-register.md` (consolidated register +
S0/S1 Verification Gate); detailed evidence is in `00-abi-equivalence-table.md`
(W1), `02-dedup-plan.md` (W2), `03-hardening-backlog.md` (W5 narrative),
`04-boot-ui-direction.md` (W6 UI). Read-only audit: this roadmap **recommends**;
no fix is implemented until the user approves it.

Sequencing principle (from the audit charter): the **kernel↔bootloader contract
must be locked before any dedup/cosmetic/UI work**. A weak/asymmetric handoff
contract is the thing that makes every other class of bug latent and silent, so
it leads. Severity order within that: S1 first, then S2 latents, then S3, then
S4/cosmetic. Items whose *priority* depends on an unresolved experiment are
flagged in the "Depends on UNVERIFIED" callout and must not be reordered ahead of
their settling experiment.

Severity tally (from the register): **S0=0, S1=4, S2=17, S3=10, S4=12** across
6 workstreams. No S0 found (confirmed W1/W2/W3/W4/W5/W6; the dual-declaration S0
is a *latent future* risk, neutralised by the appended build pins + the Phase 1
shared-crate extraction, not a present breaker).

---

## What blocks safe kernel↔bootloader handoff TODAY

This is the **must-land-before-the-user-resumes-kernel-work** set. Until these
land, every handoff the kernel consumes can be malformed/hostile in a way the
consumer does not detect, and the contract can silently drift with no build
error:

- **W1-01 (S1)** — consumer `is_valid()` is a strict subset of producer's; a
  handoff with `entry_point==0` or inconsistent `mmap` passes the consumer and is
  dereferenced. The kernel is the defending side and is under-defending.
- **W1-02 (S2)** — `MAX_CMDLINE_LEN` has no producer symbol; producer can emit an
  unbounded cmdline the kernel silently truncates. A contract the consumer
  assumes but the producer never enforces.
- **W1-03 (S3)** — `pixel_format` numbering is consumer-only; producer agreement
  is UNVERIFIED. The kernel's framebuffer math trusts an unpinned mapping.
- **Structural root cause (contract-lock driver)** — `BootHandoffV1` + all nested
  types are independently re-declared in two crates with no shared definition;
  parity is coincidental today. `00-abi-equivalence-table.md` §Step-4.2 records
  this as the latent S0. The appended `const _` pins make *layout* drift a build
  error today, but `is_valid()`/constants are not pinned — only a shared crate
  closes it structurally.
- **W3-01 (S1) + W6-04 (S3)** — the boot menu offers an ungated
  `SecurityMode::Development` on production builds (W3-01: unsigned/unverified
  kernel boots if a console attacker selects it within the timeout); the
  fail-closed-resolution path resolves ambiguity *down* to `Standard` not up to
  `Hardened` (W6-04). The kernel can be handed an unverified image.

**Phases 1–2 below are exactly this set.** Phases 3+ (W2 dedup, remaining W5
hardening, W4/cosmetic) must not precede them.

---

## Phase 0 — Pre-flight (no code; unblocks correct prioritisation)

### 0.1 — Settle the production build profile (UNVERIFIED, shared by W3/W5/W6)
- Resolves the priority of: W5-06 (S2), W3-09/W3-10 (S3/S4 build-profile),
  the W3 UNVERIFIED-1/2 and W5 UNVERIFIED-W5-4 callouts.
- Action: inspect the release build invocation —
  `grep -rn 'no-default-features|--features' Makefile* xtask* .github/ scripts/`
  and/or build `cargo build --release --no-default-features --features
  hardened-production` then `nm -C target/.../nonos_boot | grep -i groth16` to
  see whether the Groth16/zeroize symbols ship.
- Verification check: a written determination "production ships WITH default
  features (zk-groth16+zk-vk-provisioned+zk-zeroize retained)" OR "WITHOUT
  (`--no-default-features`)", with the grep/nm output pasted into the register
  UNVERIFIED block.
- Dependency: none. Run first.
- Unblocks: correct severity for W5-06 (no-op zeroize ships → escalate; else
  stays S2 latent) and W3-09/W3-10; lets Phase 4 order W5-06 correctly.

### 0.2 — Acknowledge W5-CR1 is kernel-side sequencing (no bootloader change)
- Resolves: scoping of W5-CR1 (S2, cross-ref).
- Action: record in the kernel work tracker that the LAPIC #PF
  (cr2=0xFEE000B0) is a kernel LAPIC-addressing/`clear_low_half()` ordering bug,
  NOT a bootloader contract defect (bootloader deliberately leaves no LAPIC
  mapping in PML4[256..511] — correct by contract). The mechanism is fully
  derived from offsets (register W5-CR1 / `03-hardening-backlog.md` W5-CR1);
  UNVERIFIED-W5-3 is corroborative only.
- Verification check: kernel-side ticket exists referencing W5-CR1 with the
  recommended direction (re-base `LAPIC_BASE` into the directmap, or defer
  `clear_low_half()` until LAPIC is re-based) before any post-Step-6 LAPIC
  access.
- Dependency: none. Informational gate so the bootloader roadmap does not try to
  "fix" a sound bootloader.
- Unblocks: the user's kernel-side LAPIC work (separate track; the bootloader
  contract here is sound and need not block on it).

---

## Phase 1 — Lock the ABI/handoff contract (S1/S2/S3 W1; the contract lock)

**This phase is the contract lock. Nothing in Phases 3+ may precede it.**

### 1.1 — Extract one shared `#[repr(C)]` handoff crate (structural root cause)
- Resolves: the structural root cause behind W1-01/W1-02/W1-03 and the latent
  dual-declaration S0 (`00-abi-equivalence-table.md` §Step-4.2).
- Action: create a shared crate that owns `BootHandoffV1`, all nested types
  (`FramebufferInfo`, `MemoryMap`, `AcpiInfo`, `SmbiosInfo`, `Modules`, `Timing`,
  `Measurements`, `RngSeed`, `ZkAttestation`, `FirmwareHandoff`/`FirmwareEntry`/
  `FirmwareType`), `HANDOFF_MAGIC`, `HANDOFF_VERSION`, `MAX_CMDLINE_LEN`,
  `flags::*`, `pixel_format::*`; make both `nonos-bootloader` and `nonos-kernel`
  depend on it; delete the duplicate declarations both sides.
- Verification check: both crates compile against the single definition; the
  existing dual-side `const _` offset/size pins (`00-abi-equivalence-table.md`
  §Build-proven pins, all 17 asserts) still pass with no `error[E0080]`;
  `BootHandoffV1` still `size_of == 1832`. A `git grep 'struct BootHandoffV1'`
  returns exactly one definition.
- Dependency: none (this is the head of the contract lock). Phase 0.1 not
  required for this item.
- Unblocks: 1.2 and 1.3 (a single definition is the place to fix `is_valid()`
  and add the cmdline cap once); removes the latent S0; makes future drift
  impossible by construction (not just a build error).

### 1.2 — Reconcile `is_valid()`: consumer enforces ≥ producer
- Resolves: **W1-01 (S1)**.
- Action: on the shared definition (post-1.1), make `is_valid()` enforce the
  union of both sides' invariants: `magic`, `version`, `size==size_of`,
  `entry_point != 0`, `mmap.entry_count>0 ⇒ mmap.ptr != 0`,
  `mmap.entry_count>0 ⇒ mmap.entry_size != 0`. The consumer must reject every
  handoff the producer would reject.
- Verification check: a host unit test (extend `src/boot/handoff/types/tests.rs`)
  constructs handoffs with `entry_point==0` and with `entry_count>0 && ptr==0`
  and asserts `is_valid()==false`; a valid handoff still passes; re-trace that
  `MemoryMap::entries()` (memory.rs:62-72) is now unreachable with a null ptr.
- Dependency: 1.1 (one definition to edit). Hard-blocks Phase 2+ resuming
  kernel work that trusts the handoff.
- Unblocks: the kernel can safely treat a `is_valid()`-true handoff as
  non-hostile in `mmap`/`entry_point`; closes the confused-deputy.

### 1.3 — Give the producer a `MAX_CMDLINE_LEN` and stop silent truncation
- Resolves: **W1-02 (S2)**.
- Action: with `MAX_CMDLINE_LEN` now shared (1.1), have the producer cmdline
  writer (`nonos-bootloader/src/handoff/prepare/cmdline.rs:20`) cap or hard-fail
  at `MAX_CMDLINE_LEN`; have the consumer `cmdline()`
  (`src/boot/handoff/types/handoff.rs:78-111`) reject or surface truncation
  rather than silently truncating.
- Verification check: a test feeding a `> MAX_CMDLINE_LEN` cmdline shows the
  producer refuses/caps and the consumer signals truncation (not a silent short
  string); the shared constant is the only `MAX_CMDLINE_LEN` symbol
  (`git grep MAX_CMDLINE_LEN` → one definition).
- Dependency: 1.1. Independent of 1.2 (can run in parallel once 1.1 lands).
- Unblocks: deterministic cmdline contract; closes the unbounded-producer /
  silent-consumer-truncation divergence.

### 1.4 — Pin `pixel_format` agreement (close the UNVERIFIED)
- Resolves: **W1-03 (S3)**.
- Action: with `pixel_format::*` shared (1.1), make the producer's GOP
  pixel-format write reference the shared enumeration; add a const/test asserting
  the producer's emitted set equals the shared `{RGB=0,BGR=1,RGBX=2,BGRX=3}`.
  (This also settles W1-03's "producer-agreement UNVERIFIED, scored on absence".)
- Verification check: the producer GOP fill site is located and shown to emit
  the shared constants; `bytes_per_pixel()`
  (`src/boot/handoff/types/framebuffer.rs:39-45`) is exercised against each.
- Dependency: 1.1. Lower priority than 1.2/1.3 (S3), but stays in the contract
  phase because it is a handoff-struct field.
- Unblocks: the kernel's framebuffer extent math trusts a pinned mapping.

---

## Phase 2 — Close the production trust-bypass (S1 W3-01 + its S3 sibling W6-04)

### 2.1 — Feature-gate the `Development` boot-menu entry (fail-closed menu)
- Resolves: **W3-01 (S1)** and the W6-04 (S3) resolution-path angle together.
- Action: gate the `MenuAction::Boot(SecurityMode::Development)` entry in
  `DEFAULT_ENTRIES` (`nonos-bootloader/src/menu/types/state.rs:22`) and its
  `resolve_action` arm behind `#[cfg(feature="dev-mode")]` so production /
  hardened-production builds cannot select an unsigned mode; and change
  `entry/action.rs:25` so menu timeout AND unrecognized/Cancel input resolve to
  `SecurityMode::Hardened` (most-verified), not `Standard` — ambiguity must
  decay *up*, never below the highest-verified posture (W6-04 / `04-boot-ui-
  direction.md` §5).
- Verification check: a `--no-default-features --features hardened-production`
  build has no reachable `SecurityMode::Development` (cfg-trace, mirror the W3
  feature-gate proof method: `git grep -n 'SecurityMode::Development'` shows the
  menu entry now `#[cfg]`-gated); a timeout/ESC/invalid-input simulation resolves
  to `Hardened`; the W3 feature-gate proof (b)/(d) re-runs PROVEN-safe with no
  S1 residual.
- Dependency: independent of Phase 1 (different subsystem), but it is part of
  "what blocks handoff today" so it shares Phase-1 priority and must precede
  Phases 3+. Can run in parallel with Phase 1.
- Unblocks: a production bootloader cannot hand the kernel an
  unsigned/unverified image via the console; the kernel can trust that a
  production boot ran full signature+ZK verification.

---

## Phase 3 — Remove the S2 dead/parallel trust trees (W2; mis-wire latents)

Sequenced AFTER the contract lock (Phases 1–2) per the charter: dedup is not a
contract-breaker, but these are trust latents (not mere cleanliness), so they
precede pure cosmetic/optimization work. All five have zero live callers
(`02-dedup-plan.md`, §UNVERIFIED=None) so deletion is low-risk.

### 3.1 — Delete the 4 zero-caller dead trees
- Resolves: **W2-01 (tpm/, S2)**, **W2-03 (crypto/keyring/, S2)**,
  **W2-04 (verify/, S2)**, **W2-05 (security/verify/, S2)**.
- Action: delete `tpm/`, `crypto/keyring/`, `verify/`, `security/verify/`;
  remove `pub mod tpm;`/`pub mod verify;` (`lib.rs:31`/`:40`), `crypto/mod.rs:17`
  `pub mod keyring;`, `mod verify;` from `security/mod.rs`.
- Verification check: `make nonos-mk-bootloader` builds clean; the live trust
  chain (`crypto/verify/bytes.rs:28 KEYSTORE.lock()` ←
  `run_crypto_verification`) is unchanged; `git grep` confirms no live caller of
  the deleted modules existed (re-confirm `02-dedup-plan.md` cites). ≈1,795 LOC
  removed.
- Dependency: Phases 1–2 landed (contract locked before structural churn).
- Unblocks: removes 4 `pub` mis-wireable parallel verifiers/stores; shrinks the
  trust surface a future edit could accidentally route through.

### 3.2 — Collapse `crypto/keystore_v2/` (the strongest S2→S1 latent)
- Resolves: **W2-02 (crypto/keystore_v2/, S2 trending S1)**.
- Action: delete `keystore_v2/`; migrate the 2 cosmetic call sites — source the
  fingerprint from the `crypto/keys` build constant
  (`security/init/subsystem/keys.rs:37`), drop the no-op
  `wipe_all_keys()` (`handoff/exit/cleanup.rs:29`; the real wipe is the adjacent
  `crypto::sig::wipe_signing_state()`).
- Verification check: `make nonos-mk-bootloader` builds; the fingerprint log
  still prints (now from `crypto/keys`); the live wipe path
  (`wipe_signing_state`, `crypto/sig.rs:33-40`, real `zeroize_32`) is intact;
  no `KEYSTORE_V2`/`verify_multisig` symbol remains. ≈418 net LOC removed.
- Dependency: 3.1 (do the zero-risk deletes first); Phases 1–2.
- Unblocks: removes the always-empty `verify_multisig` a future mis-route could
  verify trust against — the highest-value W2 latent.

---

## Phase 4 — Remaining S2/S3 hardening (W5/W6 not in the "today" set)

Ordered S2 before S3. None is a contract-breaker; all are post-contract-lock.

### 4.1 — Anti-rollback fail-closed (S1-adjacent rollback chain)
- Resolves: **W5-09 (S1)** [also in the "today" set conceptually, but its fix is
  a signed-region change, sequenced here after the contract crate exists so the
  rollback version can ride a shared/signed structure], **W5-03 (S2)**,
  **W5-04 (S3)**.
- Action: include the footer (≥ `image_version`) in the Ed25519-signed message
  or carry the rollback version inside the signed kernel payload (W5-09); treat
  no-TPM and `NvramReadFailed` as a hard rollback failure under
  `mode.requires_signature()` rather than a zero-floor init (W5-03/W5-04).
- Verification check: a validly-signed image with a lowered footer
  `image_version` is now rejected (signature no longer covers a mutable
  rollback input); on a no-TPM / wiped-NVRAM platform under a
  signature-requiring mode, boot fails closed. Settle UNVERIFIED-W5-1
  (QEMU+swtpm rollback experiment) to confirm.
- Dependency: Phase 1 (a signed/shared structure to anchor the version);
  Phase 0.1 (profile) for severity confirmation.
- Unblocks: anti-rollback is actually monotonic and authenticated.

### 4.2 — Validate firmware-supplied pointers before handoff
- Resolves: **W5-12 (S1)** [fix sequenced here; it gates a pointer the kernel
  dereferences, so it is in the "today" awareness set but the fix is localized
  to the producer handoff path], cross-ref **W4-05 (S4)**.
- Action: validate RSDP signature+checksum and the SMBIOS anchor before writing
  into the handoff (`handoff/config/acpi.rs:23`, `smbios.rs`); thread the
  already-checksum-validated `discover_acpi_rsdp` result instead of discarding it
  into `_hw` (also removes the W4-05 enumerate-then-drop).
- Verification check: a crafted config-table entry with a bogus `address` under
  ACPI/SMBIOS GUID is rejected before handoff; the handoff RSDP equals the
  checksum-validated `discover_acpi_rsdp` output.
- Dependency: Phases 1–2. Independent of 4.1.
- Unblocks: the kernel no longer dereferences an attacker-chosen physical
  pointer as RSDP/SMBIOS.

### 4.3 — Pre-jump secret wipe + non-optional zeroize
- Resolves: **W5-05 (S2)**, **W5-06 (S2)**.
- Action: make `wipe_transcript`/`wipe_entropy_pool` actually zero their backing
  state with the `zeroize_*` primitives and zero `BOOT_NONCE` before EBS
  (W5-05); make `hardened`/`production`/`hardened-production` transitively
  require `zk-zeroize`+`zeroize`, or make `zeroize_proof` unconditional (W5-06).
- Verification check: a memory inspection / instrumented build shows transcript,
  entropy pool, and `BOOT_NONCE` zeroed before `exit_boot_services`; the
  production profile (per Phase 0.1) compiles `zeroize_proof` as the real
  zeroizer, not the no-op stub.
- Dependency: Phase 0.1 (profile determines W5-06 severity/whether it ships
  no-op); Phases 1–2.
- Unblocks: secrets/seeds do not survive into the kernel.

### 4.4 — Measured-boot chain gaps
- Resolves: **W5-07 (S2)**.
- Action: measure the actual bootloader bytes into PCR8 unconditionally; extend
  PCR9 with the real kernel hash + real signature on every path (not only the
  ZK-verified branch); stop measuring the hardcoded all-zeros signature.
- Verification check: UNVERIFIED-W5-2 experiment (QEMU+swtpm `tpm2_pcrread
  sha256:8,9,14`) shows PCR8 ≠ SHA-256("NONOS:TPM:PROBE:v1") and PCR9 extended
  for a no-ZK-proof kernel.
- Dependency: Phases 1–2.
- Unblocks: TPM attestation actually binds the loaded bootloader/kernel/sig.

### 4.5 — Identity-window W^X + segment-cap consistency
- Resolves: **W5-10 (S2)**, **W5-08 (S3)**, **W5-02 (S3)**.
- Action: split/shrink the 64 GiB identity window so no region is W+X (W5-10);
  make `MAX_KERNEL_SEGMENTS == MAX_LOADS` or reject `load_count >
  MAX_KERNEL_SEGMENTS` (W5-08); add pairwise PT_LOAD overlap rejection in
  `validate_segments` (W5-02).
- Verification check: post-handoff page-table dump shows no W+X identity range;
  a >16-PT_LOAD signed ELF is rejected (not silently truncated); an
  overlapping-PT_LOAD ELF is rejected.
- Dependency: Phases 1–2. Note W5-10 interacts with W5-CR1 (the surviving
  window) — coordinate with the kernel-side LAPIC re-base (Phase 0.2) so
  shrinking the identity window does not change the #PF analysis.
- Unblocks: no RWX kernel-text alias survives to the kernel.

### 4.6 — Boot-menu DoS + GOP geometry + UI panel clipping
- Resolves: **W6-01 (S2)**, **W5-11 (S3)**, **W6-02 (S3)**, **W6-03 (S3)**.
- Action: track an absolute monotonic deadline keypresses cannot reset (W6-01);
  reject inconsistent GOP geometry `stride<width*4` / `stride*height>fb_size`
  (W5-11); use `saturating_sub` + panel-clip all draws (W6-02/W6-03, the §3/§4
  back-buffer + panel-clip in `04-boot-ui-direction.md`).
- Verification check: a held/flooded console key no longer prevents timeout
  (UNVERIFIED-W6-1 experiment); a small/inconsistent GOP mode is rejected; glyph
  draws clip to their panel rect.
- Dependency: Phases 1–3 (UI work is explicitly after contract + dedup per the
  charter).
- Unblocks: boot UI cannot be wedged or made to draw out of its panel.

---

## Phase 5 — Cleanliness / optimization (S4; last, per the charter)

### 5.1 — Fixed-delay + redundant-copy cleanup
- Resolves: **W4-01..W4-07, W4-09 (all S4)**, **W3-07/W3-08/W3-11/W3-12 (S4)**,
  **W3-09/W3-10 (S3/S4 build-profile, contingent on Phase 0.1)**.
- Action: read directly into a `Vec`/`Box<[u8]>` instead of UEFI-pages-then-copy
  (W4-01); replace fixed spin delays with measured stalls or delete decorative
  ones (W4-03/04/07/09); detect CPU features once (W4-06); consume or delete the
  discarded `run_hardware_discovery` (W4-05, also closes part of 4.2); replace
  `get_boot_nonce()` with the checked variant (W3-07); delete the dead
  `mock-proof` feature (W3-08); escalate Secure Boot chain failure to
  `fatal_reset` under hardened/production (W3-11); make the no-feature default
  `Standard`/Hardened-for-release (W3-09, per Phase 0.1).
- Verification check: `make nonos-mk-bootloader` builds clean; COM1 timestamp
  markers (UNVERIFIED-W4-2) show reduced boot latency; the W4-08 "no post-EBS
  alloc" invariant still holds (re-run the grep).
- Dependency: everything above. Cosmetic/perf, explicitly last.
- Unblocks: nothing security-relevant; reduces boot latency and trust-surface
  noise. W4-08/W5-01/W6-05 are clean negatives — no action, recorded only.

---

## Depends on UNVERIFIED (do not reorder ahead of the settling experiment)

- **Production build profile** (UNVERIFIED-W3-1/W3-2 = UNVERIFIED-W5-4, the
  shared one): drives the *severity* of W5-06 and W3-09/W3-10. If production
  ships `--no-default-features --features hardened-production`, `zeroize_proof`
  is a no-op in shipped binaries → escalate W5-06; if default features are
  retained, W5-06 stays an S2 latent. **Phase 0.1 must run before Phase 4.3 /
  Phase 5.1 fix-prioritisation.** Until settled, do not down-prioritise W5-06.
- **W5-CR1 LAPIC #PF (kernel-side sequencing, UNVERIFIED-W5-3)**: the
  cr2=0xFEE000B0 fault is *mechanism-proven* from offsets (register W5-CR1); the
  live trace is corroborative only. The fix is **kernel-side** (re-base
  `LAPIC_BASE` into the directmap or defer `clear_low_half()`), NOT a bootloader
  change — the bootloader contract is sound. It interacts with W5-10 (the
  surviving identity window): Phase 4.5's window shrink must be coordinated with
  the kernel LAPIC re-base (Phase 0.2) so the #PF analysis stays valid. This is
  a kernel-track dependency, called out so the bootloader roadmap does not block
  on it and does not "fix" a correct bootloader.
- **Anti-rollback hardware state (UNVERIFIED-W5-1)** and **PCR contents
  (UNVERIFIED-W5-2)**: corroborate W5-03/04/09 and W5-07's runtime effect; the
  source-level fail-OPEN/measurement-gap is proven, the experiments confirm the
  shipped-platform impact. Run alongside Phase 4.1/4.4 verification, not before
  prioritisation (severity is already set from source).
- **Boot-menu DoS timing (UNVERIFIED-W6-1)** and **back-buffer feasibility
  (UNVERIFIED-W6-2)**: corroborate/scope W6-01 and the §3 UI direction; run at
  Phase 4.6 implementation time.

---

## Self-review against plan §6 deliverables (1–6) and §7 acceptance

§6 deliverables (plan line 250 mapping):
- §6.1 Findings Register → `01-findings-register.md` consolidated (W1–W6 + gate).
  **MET.**
- §6.2 ABI Equivalence Table → `00-abi-equivalence-table.md` (golden table +
  build-proven pins + shared-crate recommendation; W1 rows lifted here).
  **MET** (source intact; lifted, not re-derived).
- §6.3 Dedup Plan → `02-dedup-plan.md` (live path by call graph; W2 rows lifted).
  **MET.**
- §6.4 Hardening Backlog → `03-hardening-backlog.md` (W5 ordered narrative; W3
  contributions in the register). **MET** (Task-6 polish residuals documented in
  the register's "Deferred-polish corrections" section, since that doc is not
  Task-8-staged).
- §6.5 Boot UI Direction → `04-boot-ui-direction.md` (W6 §1–§5; W6 hardening
  rows in the register; UI fixes sequenced Phase 4.6). **MET.**
- §6.6 Prioritized Roadmap → this document, S0/S1 first, contract locked
  (Phases 1–2) before dedup (Phase 3) before hardening (Phase 4) before
  cosmetic (Phase 5), with explicit "blocks handoff today" + "depends on
  UNVERIFIED" sections. **MET.**

§7 acceptance (plan line 251):
- *No S0/S1 UNVERIFIED* → register `## S0/S1 Verification Gate`: 0 S0 (confirmed),
  4 S1 each with already-established build-proof / fully-derived cite / this-task
  re-trace; none UNVERIFIED; zero downgrades. **MET.**
- *ABI table complete, no "looks the same"* → `00-abi-equivalence-table.md`
  derives every offset from the `#[repr(C)]` algorithm and build-proves the pins;
  the one genuinely-open item (`pixel_format` producer agreement) is explicitly
  scored UNVERIFIED-on-absence (W1-03), not eyeballed. **MET.**
- *Duplicate recs name the live path by call graph* → W2 rows + `02-dedup-plan.md`
  each cite a resolved call site or a cited absence. **MET.**
- *Roadmap names handoff blockers* → "What blocks safe kernel↔bootloader handoff
  TODAY" section enumerates the exact must-land set (W1-01/02/03 + structural
  root cause + W3-01/W6-04) = Phases 1–2. **MET.**

**Coverage statement: §6 (1–6) and §7 acceptance are fully MET, with one
documented residual** — the Task-6 deferred-polish edits to
`03-hardening-backlog.md` (the "Ordered S0→S4" header rationale and the W5-CR1
prose anchor) are recorded in the register's "Deferred-polish corrections"
section and the W5-CR1 canonical anchor is corrected in the register, rather than
editing `03-hardening-backlog.md` directly, because the Task-8 mandate stages
ONLY `01-findings-register.md` and `05-prioritized-roadmap.md`. This is an
intentional, written residual (the consolidated register is the source of
record), not a coverage gap. No other gaps.
