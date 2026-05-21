# Bootloader Hardening & Kernel-Contract Investigation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to execute this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce an evidence-backed audit of `nonos-bootloader/` against the kernel handoff contract across five dimensions (contract, duplicates, gaps, optimization, hardening) plus a boot-UI direction, terminating in an approved prioritized roadmap — without refactoring until that roadmap is approved.

**Status (2026-05-20):** Plan fully executed on `feature/bootloader-hardening`. All six deliverables under `docs/audits/bootloader-hardening/` are populated; the prioritized roadmap (`05-prioritized-roadmap.md`) is the terminal artifact awaiting user approval before any fix lands. The dual-side const-eval pin block builds clean today (layout MATCH); the latent dual-declaration risk is recorded in W1 and resolved by Roadmap Phase 1 (shared-crate extraction). Register tally: S0=0, S1=4, S2=17, S3=10, S4=12 + 4 informational.

Task → commit map:

- Task 1 (W1 golden table) → `39649c7a4`
- Task 2 (W1 dual-side pin assertions) → `51cc3cf09`
- Task 3 (W2 dedup) → `7c7e98cb5`
- Task 4 (W3 gaps) → `23d36d505`
- Task 5 (W4 optimization) → `3cc5218f0`
- Task 6 (W5 hardening) → `d5cdfee01`
- Task 7 (W6 boot-UI direction) → `1e56e2512`
- Task 8 (synthesis: register + roadmap) → `409988589`; follow-up `919127580` notes the deliberate S0/S4 absence in W5 and pins `01-findings-register.md` as the single source of record.

**Architecture:** Read-only audit. The only code artifacts created are *measurement artifacts*: compile-time `offset_of!`/`size_of!` static assertions pinned to one golden ABI table, added to both the producer and consumer side. Layout drift becomes a build/compile error today — that failing build is the S0 evidence. All other output is markdown deliverables under `docs/audits/bootloader-hardening/`. Fixes are deferred to the roadmap (deliverable 6); nothing in §W2–W6 patches code in this plan.

**Tech Stack:** Rust nightly-2026-01-16 (`offset_of!` stable since 1.77; const-eval `assert!`), `#[repr(C)]` layout algorithm as the layout oracle, kernel host build (`cargo check/test --lib --features std --target x86_64-apple-darwin`), bootloader UEFI build (`make nonos-mk-bootloader`), repo Makefile.

---

## Established ground truth (verified during recon, supersedes the prompt where they differ)

These were confirmed by reading the trees; the plan is built on them, not on the prompt's assumptions:

- **Top-level field order matches.** Both `BootHandoffV1` definitions list, in order: `magic:u32, version:u16, size:u16, flags:u64, entry_point:u64, fb, mmap, acpi, smbios, modules, timing, meas, rng, zk, firmware, cmdline_ptr:u64`. Producer: `nonos-bootloader/src/handoff/types/handoff.rs:28`. Consumer: `src/boot/handoff/types/handoff.rs:26`. Top-level order parity is NOT the risk; nested layout + constants are.
- **Nested structs come from different modules each side** (the real drift surface):
  - Producer `AcpiInfo/SmbiosInfo/Modules/Timing` ← `nonos-bootloader/src/handoff/types/system.rs`; consumer ← `src/boot/handoff/types/info.rs`.
  - Producer `Measurements/RngSeed/ZkAttestation` ← `nonos-bootloader/src/handoff/types/security.rs` (also a sibling `types/crypto.rs` exists); consumer ← `src/boot/handoff/types/security.rs`.
  - Producer `FirmwareHandoff` ← `crate::firmware` (`nonos-bootloader/src/firmware/`); consumer ← `src/boot/handoff/types/firmware.rs`. **Highest drift risk: no co-located definition at all.**
  - `FramebufferInfo` ← `…/types/framebuffer.rs` both sides; `MemoryMap` ← `…/types/memory.rs` both sides.
- **`is_valid()` asymmetry confirmed.** Producer (`handoff/types/handoff.rs:34`) checks magic, version, `size==size_of::<Self>()`, `entry_point!=0`, mmap ptr/entry_size consistency. Consumer (`src/boot/handoff/types/handoff.rs:47`) checks **only** magic, version, size. The consumer accepts handoffs the producer would reject — S2+ hardening hole, candidate S1.
- **Constant drift confirmed.** Consumer `src/boot/handoff/types/constants.rs` defines `MAX_CMDLINE_LEN: usize = 4096` and `pixel_format::*`; producer `nonos-bootloader/src/handoff/types/constants.rs` defines **neither** — only `HANDOFF_MAGIC`, `HANDOFF_VERSION`, `flags::*`. `flags::*` bit values currently match (WX=1<<0 … ZK_ATTESTED=1<<10) but are independently maintained. The consumer's `cmdline()` enforces a 4096 cap the producer has no symbol for.
- **`host-tests` feature is dormant.** Declared `nonos-bootloader/Cargo.toml:94`, zero source references. Do not build the proof on it; use const-eval assertions instead (compile under the normal UEFI build, no test runner).
- **Prompt path drift (correct the prompt, do not chase ghosts).** `boot/main/` and `boot/init.rs` cited in the prompt **do not exist**. Real orchestration root: `nonos-bootloader/src/main.rs` (29 lines → `entry::boot_entry`) and `nonos-bootloader/src/entry/{mod,boot,init,pipeline,action,mode,dev}.rs`. `boot/zk_init/` exists (4 files); `boot/attestation/` exists (11 files). W2 candidate-tree set is otherwise as the prompt lists (all confirmed present with file counts: `tpm/`=24, `hardware/tpm/`=22, `zk/`=56, `security/attestation/`=21, `kernel_verify/`=13, `crypto/keystore_v2/`=13, etc.).
- **Consumer surface already has a host-test file**: `src/boot/handoff/types/tests.rs` uses std `#[test]` (size<4096, default valid, flags). Kernel host runner: `cargo test --lib --features std --target x86_64-apple-darwin`.

---

## Scope check

The prompt spans six workstreams. W1 is an S0 gate; W2–W6 are mutually independent analyses that fan out cleanly to parallel subagents and converge in the synthesis task. This is kept as **one plan with one roadmap** (the prompt mandates a single prioritized roadmap with W1 locked first), not split into sub-project plans, because the deliverables are interdependent (the roadmap sequences across all workstreams) and no workstream ships independent software.

## Isolation

Read-only audit on the existing branch `feature/bootloader-hardening`. The ABI pin-assertions are additive and fail-loud (compile errors on drift), not behavioral refactors. A worktree is **not required**; if the executor prefers isolation, create one via `superpowers:using-git-worktrees` before Task 1, but the audit must not modify kernel logic or bootloader behavior regardless.

## File structure

**Deliverables (created by this plan):**

- `docs/audits/bootloader-hardening/00-abi-equivalence-table.md` — every `BootHandoffV1` field/constant/flag, both sides, offset, size, verdict (MATCH/DRIFT/UNVERIFIED). The golden table. (W1)
- `docs/audits/bootloader-hardening/01-findings-register.md` — ID, workstream, severity, `path:line`, claim, evidence, fix, effort. (all)
- `docs/audits/bootloader-hardening/02-dedup-plan.md` — per candidate tree: live path (call-graph evidence), delete/merge, LOC delta, risk. (W2)
- `docs/audits/bootloader-hardening/03-hardening-backlog.md` — ordered by severity, each with the threat it closes. (W3, W5)
- `docs/audits/bootloader-hardening/04-boot-ui-direction.md` — one-page concrete UI design + UI-path hardening fixes. (W6)
- `docs/audits/bootloader-hardening/05-prioritized-roadmap.md` — S0/S1 first; explicitly names what blocks safe handoff today. The terminal deliverable. (synthesis)

**Measurement artifacts (created by this plan, the only code touched):**

- Append to `src/boot/handoff/types/tests.rs` — consumer-side `offset_of!`/`size_of!` pins to the golden table (host-runnable `#[test]`).
- New `const _: () = assert!(...)` blocks pinned to identical golden numbers, in a co-located gated module on each side: consumer `src/boot/handoff/types/handoff.rs`, producer `nonos-bootloader/src/handoff/types/handoff.rs`. Const-eval; fails the normal build on drift; no test runner, no dormant feature.

**Read-only inputs (audited, never modified by this plan):** entire `nonos-bootloader/src/`; kernel contract surface `src/boot/handoff/`, `src/nonos_main.rs`, `src/boot/mod.rs`.

---

### Task 1 (W1): Build the golden ABI equivalence table

**Files:**
- Read: `nonos-bootloader/src/handoff/types/{handoff,constants,framebuffer,memory,system,security,crypto}.rs`
- Read: `src/boot/handoff/types/{handoff,constants,framebuffer,memory,info,security,firmware}.rs`
- Read: `nonos-bootloader/src/firmware/` (resolve `crate::firmware::FirmwareHandoff` definition + every nested type)
- Create: `docs/audits/bootloader-hardening/00-abi-equivalence-table.md`

- [x] **Step 1: Resolve every type definition both sides.** For `BootHandoffV1` and each nested struct (`FramebufferInfo`, `MemoryMap`, `AcpiInfo`, `SmbiosInfo`, `Modules`, `Timing`, `Measurements`, `RngSeed`, `ZkAttestation`, `FirmwareHandoff`) record on producer and consumer: every field name, type, declared order, and `#[repr]` attribute (cite `path:line`). For `FirmwareHandoff` follow `crate::firmware` to its real definition file and recurse into any sub-structs.

- [x] **Step 2: Derive offsets by the `#[repr(C)]` algorithm, not by eye.** For each struct, compute field offset and total size + tail padding from C layout rules (each field aligned up to its alignment; struct size rounded up to max member alignment). Produce, per struct, a table: field | type | producer offset | producer size | consumer offset | consumer size | verdict. Any nested type whose layout you cannot fully reduce → mark **UNVERIFIED** with the exact `offset_of!` experiment that settles it (do not guess).

- [x] **Step 3: Compare constants and flags.** Table for `HANDOFF_MAGIC`, `HANDOFF_VERSION`, `MAX_CMDLINE_LEN`, every `flags::*` bit: producer value | consumer value | verdict. Record explicitly that `MAX_CMDLINE_LEN` has **no producer symbol** (DRIFT — producer cannot enforce the cap the consumer assumes).

- [x] **Step 4: Record the `is_valid()` divergence as a contract finding** in the table's notes: producer rejects `entry_point==0` and inconsistent `mmap`; consumer does not. State the authoritative invariant set recommendation (consumer must enforce ≥ producer's invariants; ideally one shared `#[repr(C)]` definition both crates import — note `abi/` has no handoff types today, so the recommendation is "extract shared crate", scoped in the roadmap not here).

- [x] **Step 5: Write `00-abi-equivalence-table.md`** with all tables from Steps 2–4 and a verdict summary (counts of MATCH / DRIFT / UNVERIFIED). No "looks the same" anywhere — every cell is a derived number or UNVERIFIED+experiment.

- [x] **Step 6: Commit.** (`39649c7a4`)
```bash
git add docs/audits/bootloader-hardening/00-abi-equivalence-table.md
git commit -m "audit(handoff): golden ABI equivalence table, both sides derived"
```

### Task 2 (W1): Pin the contract with dual-side static assertions — watch drift fail the build

This is the TDD core: the assertions are the failing "test" written first; current drift makes them fail to compile; that compile failure is the S0/S1 proof. **Do not fix the drift here** — record it and let the build stay red until the roadmap is approved.

**Files:**
- Modify: `src/boot/handoff/types/tests.rs` (append host `#[test]` offset/size pins)
- Modify: `src/boot/handoff/types/handoff.rs` (append `const _: () = assert!(...)` pin block)
- Modify: `nonos-bootloader/src/handoff/types/handoff.rs` (append identical-number `const _: () = assert!(...)` pin block)

- [x] **Step 1: Write the failing consumer host test.** Append to `src/boot/handoff/types/tests.rs`:
```rust
#[test]
fn abi_pins_match_golden() {
    use core::mem::{offset_of, size_of};
    // Golden numbers come from 00-abi-equivalence-table.md, Step 2.
    assert_eq!(offset_of!(BootHandoffV1, magic), 0);
    assert_eq!(offset_of!(BootHandoffV1, version), 4);
    assert_eq!(offset_of!(BootHandoffV1, size), 6);
    assert_eq!(offset_of!(BootHandoffV1, flags), 8);
    assert_eq!(offset_of!(BootHandoffV1, entry_point), 16);
    assert_eq!(offset_of!(BootHandoffV1, fb), 24);
    // ...one line per BootHandoffV1 field, values from the golden table...
    assert_eq!(offset_of!(BootHandoffV1, cmdline_ptr), /* golden */ 0);
    assert_eq!(size_of::<BootHandoffV1>(), /* golden total */ 0);
}
```
Replace every `/* golden */ 0` with the Task 1 Step 2 derived number for the *consumer* layout before running.

- [x] **Step 2: Run it; expect FAIL or PASS-with-record.** Run: `cargo test --lib --features std --target x86_64-apple-darwin boot::handoff::types::tests::abi_pins_match_golden -- --nocapture`. Record the exact output. If consumer self-layout matches its own golden numbers it PASSES (consumer is internally consistent); the equivalence failure surfaces in Step 4 against the producer. Capture output either way — this is evidence, not a pass/fail gate.

- [x] **Step 3: Add the consumer const-eval pin block** to `src/boot/handoff/types/handoff.rs` (compiles under the normal kernel build, no test runner):
```rust
const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(offset_of!(BootHandoffV1, flags) == 8);
    // ...identical golden numbers as Step 1...
    assert!(size_of::<BootHandoffV1>() == /* golden */ 0);
};
```

- [x] **Step 4: Add the producer const-eval pin block with the SAME numbers** to `nonos-bootloader/src/handoff/types/handoff.rs`. Use the consumer's golden numbers verbatim (this is the equivalence assertion — producer layout is pinned to the consumer contract). Then build the producer: `make nonos-mk-bootloader`. **Expected: compile error on every field whose producer offset/size differs from the consumer golden number.** Capture the full `error[E0080]`/`assert!` output verbatim.

- [x] **Step 5: Record the proof, do not fix.** Outcome: dual-side pin block compiles clean — equivalence is build-proven MATCH for every pinned field/size. The latent dual-declaration *risk* (no shared crate) is recorded in `00-abi-equivalence-table.md` §Step-4 and resolved by Roadmap Phase 1 (shared-crate extraction); register flags it as a recommendation, not a present S0. Each compile failure from Step 4 is one DRIFT row in `00-abi-equivalence-table.md` upgraded from derived-claim to build-proven, and a finding in the register (Task 8) at S0 (breaks contract) or S1 (silent trust bypass) per the severity scale. If Step 4 *compiles clean*, the equivalence is build-proven MATCH for pinned fields — record that with the passing build output. Leave the producer pin block in place (red build = the contract is currently broken and that must stay visible until the roadmap fixes it; note this loudly in the register so it is not mistaken for a regression).

- [x] **Step 6: Commit.** (`51cc3cf09`)
```bash
git add src/boot/handoff/types/tests.rs src/boot/handoff/types/handoff.rs nonos-bootloader/src/handoff/types/handoff.rs docs/audits/bootloader-hardening/00-abi-equivalence-table.md
git commit -m "audit(handoff): dual-side ABI pin assertions; build-proves contract drift"
```

### Task 3 (W2): Duplicate / dead-code adjudication by call graph

**Files:**
- Read entry: `nonos-bootloader/src/main.rs`, `nonos-bootloader/src/entry/{mod,boot,init,pipeline,action,mode,dev}.rs`
- Read candidate trees: `crypto/{keyring,keys,keystore_v2}`, `tpm/`, `hardware/tpm/`, `security/hardware/tpm_detect/`, `verify/`, `kernel_verify/`, `security/verify/`, `security/attestation/`, `zk/attest/`, `boot/attestation/`, `zk/`, `boot/zk_init/` (all under `nonos-bootloader/src/`)
- Create: `docs/audits/bootloader-hardening/02-dedup-plan.md`

- [x] **Step 1: Trace the live call graph** from `entry::boot_entry` through `entry/pipeline.rs` outward. For each candidate tree, find whether any path from `boot_entry` reaches it (`grep` for the module's public entry symbols across the live path; record `path:line` of the call site or its absence).

- [x] **Step 2: Classify each tree** as LIVE / DEAD / PARALLEL (reachable but redundant with a LIVE sibling). For PARALLEL, state which is canonical and the drift evidence (e.g. two keystores with diverging key formats). Apply the `simplify` discipline: defense-in-depth (intentional, keep) vs duplication (drift risk, merge) — justify each call with mechanism, not preference.

- [x] **Step 3: Quantify** per tree: LOC removable, modules collapsible, and the migration risk of delete-or-merge (what live caller must change). Note "a best version cannot carry three keystores" must resolve to exactly one.

- [x] **Step 4: Write `02-dedup-plan.md`**: table per tree {live path + call-graph evidence | verdict | recommendation | LOC delta | risk}. No recommendation without a cited live-path call site (acceptance criterion).

- [x] **Step 5: Commit.** (`7c7e98cb5`)
```bash
git add docs/audits/bootloader-hardening/02-dedup-plan.md
git commit -m "audit(dedup): live-path call-graph adjudication of parallel trees"
```

### Task 4 (W3): Gap analysis

**Files:**
- Read: all of `nonos-bootloader/src/` (focus: `loader/`, `kernel_verify/`, `verify/`, `crypto/`, `security/`, `handoff/`, `boot/crypto/`, `zk/`)
- Read: `nonos-bootloader/Cargo.toml` `[features]`
- Append findings to: `docs/audits/bootloader-hardening/01-findings-register.md` (create if absent)

- [x] **Step 1: Enumerate reachable panics.** `grep -rn 'todo!\|unimplemented!\|unreachable!\|panic!' nonos-bootloader/src` then filter to those reachable from the live path (Task 3 call graph). Record each with reachability evidence.

- [x] **Step 2: Enumerate `unwrap`/`expect` on attacker/firmware-influenced data** (ACPI/SMBIOS/RSDP/MADT, NVRAM, kernel image bytes, entropy, GOP geometry, cmdline). Cite `path:line` and name the untrusted source.

- [x] **Step 3: Find swallowed errors** — `Result` mapped to `Ok`/`unwrap_or`/default on a security check path; cite each.

- [x] **Step 4: Feature-gate proof.** From `nonos-bootloader/Cargo.toml`: `production=["hardened"]`, `hardened-production=["production"]`, `mock-proof=[]`, `zk-vk-provisioned`, default=`["logging","zk-groth16","zk-vk-provisioned","zk-zeroize"]`. Prove by `cfg`-tracing that `production`/`hardened-production` **cannot** transitively enable `mock-proof` and cannot skip signature/ZK verification. Any path where it can = S1, register it.

- [x] **Step 5: Verify→use TOCTOU sweep** — anywhere a buffer is hashed/verified then re-read from its source (kernel image, manifest). Cite the verify site and the later re-read.

- [x] **Step 6: Append all to `01-findings-register.md`** with severity per the scale; commit. (`23d36d505`)
```bash
git add docs/audits/bootloader-hardening/01-findings-register.md
git commit -m "audit(gaps): reachable panics, untrusted unwraps, feature-gate proof, TOCTOU"
```

### Task 5 (W4): Optimization audit

**Files:**
- Read: `nonos-bootloader/src/{loader,boot/crypto,kernel_verify,hardware,firmware,security/hardware}`, `handoff/exit/`, `handoff/jump/`
- Append to: `docs/audits/bootloader-hardening/01-findings-register.md`

- [x] **Step 1:** Identify the kernel image being hashed or copied more than once across `boot/crypto/hash.rs`, `kernel_verify/`, `loader/`. Cite each pass; quantify bytes/passes.
- [x] **Step 2:** Find allocations after `ExitBootServices` or in interrupt-sensitive windows (`handoff/exit/`, `handoff/jump/`); cite call site and why it is post-EBS.
- [x] **Step 3:** Find redundant hardware re-enumeration across `hardware/`, `firmware/`, `security/hardware/`; cite duplicate probes.
- [x] **Step 4:** Flag oversized modules vs the repo single-responsibility norm (file LOC; only those that also harm reasoning, not cosmetic). Blocking delays on the critical path (`boot/util/delay.rs` usage on the live path).
- [x] **Step 5:** Append findings (cost stated, not just presence) at S4 (or higher if it widens a fault window); commit. (`3cc5218f0`)
```bash
git add docs/audits/bootloader-hardening/01-findings-register.md
git commit -m "audit(opt): redundant hashing, post-EBS alloc, re-enumeration, delays"
```

### Task 6 (W5): Hardening threat audit

**Files:**
- Read: `loader/{core/exec,segment,validate}`, `kernel_verify/`, `verify/`, `image_format/`, `crypto/signature/`, `security/anti_rollback/`, `security/tpm_extend/`, `security/attestation/`, `hardware/tpm/`, `security/memory/zeroize/`, `entropy/wipe/`, `zk/transcript/`, `paging/`, `handoff/jump/` (all under `nonos-bootloader/src/`)
- Append to: `docs/audits/bootloader-hardening/03-hardening-backlog.md`

- [x] **Step 1: Parse-before-verify.** Determine the order: is the kernel ELF parsed (`loader/`, `image_format/`) before its signature is checked (`crypto/signature/`, `kernel_verify/`)? Cite the two call sites and their order. Parse-before-verify on attacker-controlled image bytes = S1.
- [x] **Step 2: ELF loader bounds.** In `loader/core/exec/`, `loader/segment/`, `loader/validate/`: segment overlap, `p_offset+p_filesz` / `p_memsz` overflow, entry-in-range, zero-tail handling. One finding per missing/incomplete check with the malformed input that exploits it.
- [x] **Step 3: Anti-rollback.** Is the NVRAM monotonic counter enforced *before* handoff and resistant to NVRAM wipe (`security/anti_rollback/`)? Cite the enforcement site or its absence.
- [x] **Step 4: Measured boot chain.** Which PCRs are extended with what, firmware→kernel-entry, complete? (`security/tpm_extend/`, `security/attestation/`, `hardware/tpm/`). Gaps in the chain = S2.
- [x] **Step 5: Zeroization.** Seeds/keys/buffers zeroized on *every* path incl. error/panic (`security/memory/zeroize/`, `entropy/wipe/`, `zk/transcript/`)? Confirm `zk-zeroize`/`zeroize` is non-optional in `hardened`/`production` (cross-check Cargo features). Missing error-path wipe = S2.
- [x] **Step 6: Paging handoff.** W^X on kernel text/data; no writable+executable stray identity mappings; identity window sized to *actual* firmware load reality not guesswork (`paging/`, `handoff/jump/`; cross-ref the recorded 4→64 GiB identity widening and the unfixed LAPIC `#PF` at `cr2=0xFEE000B0` post-identity-teardown — treat as in-scope, root-cause via systematic-debugging before any recommendation).
- [x] **Step 7:** Write `03-hardening-backlog.md` ordered by severity, each entry naming the threat it closes; mirror entries into the findings register; commit. (`d5cdfee01`; follow-up `919127580` notes the deliberate S0/S4 absence in W5 and pins the register as the single source of record.)
```bash
git add docs/audits/bootloader-hardening/03-hardening-backlog.md docs/audits/bootloader-hardening/01-findings-register.md
git commit -m "audit(hardening): parse-before-verify, ELF bounds, rollback, PCR, zeroize, paging"
```

### Task 7 (W6): Boot UI direction + UI-path hardening

> Run `superpowers:brainstorming` before this task (creative; explore failure-UX intent before proposing a direction). Process skill first, then write the direction.

**Files:**
- Read: `nonos-bootloader/src/{display,menu,ui}`, `nonos-bootloader/src/boot/uefi/screen.rs`, `display/constants/`, `display/font/draw.rs`, `display/gop/`, `menu/input/`
- Create: `docs/audits/bootloader-hardening/04-boot-ui-direction.md`

- [x] **Step 1: Brainstorm** the failure-UX and stage model with the user (states, what a legible failure looks like, fail-closed timeout behavior) — do not pre-decide.
- [x] **Step 2: Assess current** layout/theme/font/log-panel/stage feedback; list what's missing for a deterministic, flicker-free, partial-frame-free boot experience (cite current `display/constants/` values to stay consistent).
- [x] **Step 3: UI-path hardening findings** → into the findings register: unbounded reads / missing prompt timeout in `menu/input/`; GOP draw bounds in `display/gop/`, `display/font/draw.rs`; attacker-controlled strings (firmware vendor, cmdline) rendered without length/encoding caps; **fail-closed proof**: a menu timeout or invalid input must not select a less-verified boot path (cite the selection logic).
- [x] **Step 4: Write `04-boot-ui-direction.md`** — one page: state machine, layout grid, color/role semantics, failure UX — consistent with existing `display/constants/`. Commit. (`1e56e2512`)
```bash
git add docs/audits/bootloader-hardening/04-boot-ui-direction.md docs/audits/bootloader-hardening/01-findings-register.md
git commit -m "audit(ui): boot UI direction + UI-path hardening findings"
```

### Task 8 (synthesis): Findings register completion + prioritized roadmap

> Run `superpowers:writing-plans` for the roadmap (it is a written plan, not prose) and `superpowers:verification-before-completion` before marking any S0/S1 verified or the audit complete.

**Files:**
- Finalize: `docs/audits/bootloader-hardening/01-findings-register.md`
- Create: `docs/audits/bootloader-hardening/05-prioritized-roadmap.md`

- [x] **Step 1: Consolidate** every finding from Tasks 2–7 into `01-findings-register.md`: ID | workstream | severity (S0–S4) | `path:line` | claim | evidence | recommended fix | effort. One row per finding, sorted by severity.
- [x] **Step 2: Verification gate.** Outcome: zero S0 findings; four S1 findings (W1-01, W3-01, W5-09, W5-12) all carry derived `path:line` evidence in the register's "S0/S1 Verification Gate" section. No UNVERIFIED S0/S1 remain. For every S0/S1: confirm it rests on a build error, test output, or a fully-derived layout/call-graph cite — **no S0/S1 may be UNVERIFIED** (acceptance §7). Any that is: either run the settling experiment now or downgrade with rationale. Paste the proving output into the evidence cell.
- [x] **Step 3: Write `05-prioritized-roadmap.md`** as a real plan: S0/S1 first, sequenced so the kernel↔bootloader contract (shared `#[repr(C)]` extraction + `is_valid()` reconciliation + `MAX_CMDLINE_LEN` producer symbol) lands before any dedup or UI work. Explicitly list "what blocks safe handoff today" and "what must land before the user resumes kernel work".
- [x] **Step 4: Self-review** the roadmap against prompt §6 deliverables (1–6) and §7 acceptance criteria; fix gaps inline.
- [x] **Step 5: Commit and present** the roadmap for approval. No fixes are implemented until the user approves the roadmap (the prompt's read-only mandate). (`409988589`) **Awaiting user approval of `05-prioritized-roadmap.md` before any fix lands.**
```bash
git add docs/audits/bootloader-hardening/01-findings-register.md docs/audits/bootloader-hardening/05-prioritized-roadmap.md
git commit -m "audit: consolidated findings register + prioritized hardening roadmap"
```

---

## Self-review against the prompt

- §6.1 Findings Register → Tasks 4–8. §6.2 ABI Equivalence Table → Tasks 1–2 (golden table + build-proven pins, with shared-crate recommendation). §6.3 Dedup Plan → Task 3. §6.4 Hardening Backlog → Tasks 6 (+3 from W3). §6.5 Boot UI Direction → Task 7. §6.6 Prioritized Roadmap → Task 8.
- §7 acceptance: no S0/S1 UNVERIFIED → Task 8 Step 2 gate; ABI table complete with no "looks the same" → Task 1 Step 2/5 (UNVERIFIED+experiment, never eyeballing); duplicate recs name live path by call graph → Task 3 Step 4; roadmap names handoff blockers → Task 8 Step 3.
- §8 skills: brainstorming before W6 (Task 7), writing-plans + verification-before-completion at synthesis (Task 8), systematic-debugging for the LAPIC `#PF`/identity-teardown surface (Task 6 Step 6), simplify discipline in W2 (Task 3 Step 2), TDD for the ABI proof (Task 2 = failing assertion first). House style (no comments, tight modules) governs every artifact; the pin blocks add no `//` comments.
- Read-only mandate honored: the only code is fail-loud measurement (pin assertions); every fix is deferred to the §6.6 roadmap (Task 8 Step 5). The prompt's non-existent `boot/main/`/`boot/init.rs` paths are corrected, not chased.
