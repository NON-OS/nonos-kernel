# NØNOS Bootloader — Hardening & Kernel-Contract Investigation Prompt

> Branch: `feature/bootloader-hardening`
> Target: `nonos-bootloader/` (~37k LOC, UEFI stage-0) measured against the kernel at workspace root.
> Mode: read-only audit first. Produce a findings register and a prioritized plan. Do **not** refactor until the plan is approved.

## 0. Operating mindset — principal Rust kernel engineer, first principles

Adopt the stance of a principal-level Rust kernel engineer who personally owns the boot↔kernel trust boundary. A wrong byte in this contract is not a bug — it is a silent root compromise or an unbootable machine that no test in the kernel will ever catch.

- **Derive, don't recognize.** Every claim must follow from primitives: the `#[repr(C)]` layout algorithm (field order, alignment, tail padding), the SysV/UEFI x86-64 ABI, the UEFI boot-services lifecycle, the paging architecture, the ELF spec. "It compiles", "the names match", "it's always worked", and "the field order looks the same" are not evidence. If a conclusion cannot be reduced to mechanism, it is **UNVERIFIED** — say so and state the exact experiment that would settle it.
- **Reason in invariants.** For every trust decision: name the invariant, where it is established, where it is relied upon, and the precise input that violates it. Track the lifetime and mapping of every pointer the kernel will dereference after ExitBootServices and after identity/directmap teardown.
- **Adversarial by default.** Firmware tables, NVRAM, the kernel image, entropy, timing, and input are attacker-influenced until proven otherwise. Fail closed: any ambiguity must resolve toward the *more* verified path, never the less.
- **No deference to existing code.** Existing structure is evidence of intent, not proof of correctness. Three keystores is not "defense in depth" until you have proven it; drift is the null hypothesis.
- **Mechanism-level explanation (Jon Gjengset style).** Explain *why it must be so*, at the level of bytes, offsets, and CPU/firmware behavior — not *what the code does*. Precision over breadth; no hand-waving.

## 1. Mission

You are auditing a production UEFI bootloader for a zero-trust, capability-enforced microkernel.
Deliver a precise, evidence-backed assessment in five dimensions:

1. **Kernel contract** — prove or disprove that the bootloader↔kernel handoff ABI is byte-for-byte sound.
2. **Duplicates** — locate redundant subsystem trees and dead/parallel implementations.
3. **Gaps** — missing validation, unhandled failure paths, stubs, silent fallbacks.
4. **Optimization** — wasted work, oversized modules, redundant passes, UEFI-unsafe allocation.
5. **Hardening** — every place an attacker-controlled or untrusted input reaches a trust decision.

Every claim must cite `path:line`. No speculation presented as fact. If you cannot verify, label it **UNVERIFIED** and say what evidence would settle it.

## 2. Established context (verified before this prompt was written)

- The bootloader producer is `nonos-bootloader/src/handoff/` (`pub mod handoff` in `nonos-bootloader/src/lib.rs:28`). The kernel consumer is the **separate** tree `src/boot/handoff/`. There is **no shared ABI crate** — `abi/` contains no handoff types. The two `BootHandoffV1` structs are hand-synced.
- Drift already exists: `nonos-bootloader/src/handoff/types/handoff.rs` `is_valid()` checks `magic, version, size, entry_point != 0, mmap.ptr/entry_size consistency`; `src/boot/handoff/types/handoff.rs` `is_valid()` checks only `magic, version, size`. The producer and consumer disagree on what a valid handoff is.
- `BootHandoffV1` embeds sub-structs each defined twice (producer + consumer): `FramebufferInfo`, `MemoryMap`, `AcpiInfo`, `SmbiosInfo`, `Modules`, `Timing`, `Measurements`, `RngSeed`, `ZkAttestation`, `FirmwareHandoff`, plus `magic/version/size/flags/cmdline_ptr` scalars. All are `#[repr(C)]`. Field order *looks* identical at the top level; this is unproven for every nested struct, padding, and constant (`HANDOFF_MAGIC`, `HANDOFF_VERSION`, flag bits, `MAX_CMDLINE_LEN`).
- Candidate duplicate trees inside `nonos-bootloader/src/` to adjudicate (which is live, which is dead, can they merge):
  - Keystores: `crypto/keyring/`, `crypto/keys/`, `crypto/keystore_v2/`
  - TPM: `tpm/`, `hardware/tpm/`, `security/hardware/tpm_detect/`
  - Kernel verification: `verify/`, `kernel_verify/`, `security/verify/`
  - Attestation: `security/attestation/`, `zk/attest/`, `boot/attestation/`
  - ZK init: `zk/`, `boot/zk_init/`
  - Boot orchestration: live spine is `main.rs` → `entry/` (`boot/main/` and `boot/init.rs` do not exist; do not search for them)
- Known live kernel-side issue from memory (verify, do not assume current): kernel handoff tears down the identity map in `init_unified_vm` Step 6; recent bootloader commits widened the identity window 4 GiB → 64 GiB to fix an ExitBootServices `#PF` on OVMF/QEMU 10.2 (`constants.rs`, `map_identity.rs`, `orchestrate.rs`). LAPIC EOI `#PF` at `cr2=0xFEE000B0` after identity teardown is recorded as unfixed. Treat the identity-map sizing and post-ExitBootServices fault surface as in-scope hardening, not settled.

## 3. Scope and non-goals

**In scope:** everything under `nonos-bootloader/`, and the kernel-side consumer surface only where it defines or reads the contract (`src/boot/handoff/`, `src/nonos_main.rs`, `src/boot/mod.rs`, kernel ELF/entry expectations, paging expectations at handoff).

**Out of scope:** changing kernel internals beyond the handoff contract; the user is independently fixing the kernel. Flag kernel-side contract bugs as findings; do not patch kernel logic.

**Non-goals:** cosmetic churn, comment additions (this codebase is deliberately comment-free; match it), speculative rewrites.

## 4. Workstreams

### W1 — Handoff ABI equivalence (highest priority)

Produce a field-by-field equivalence table for `BootHandoffV1` and every nested struct, both sides:

- For each field: name, type, offset, size, on both producer and consumer. Compute offsets from `#[repr(C)]` rules including padding; do not eyeball. Use `core::mem::offset_of`/`size_of` reasoning or a host test.
- Compare every shared constant and flag bit: `HANDOFF_MAGIC`, `HANDOFF_VERSION`, `MAX_CMDLINE_LEN`, all `flags::*`. A mismatched flag bit is a silent boot-trust failure.
- Reconcile the `is_valid()` asymmetry: decide the authoritative invariant set and which side enforces it. The consumer accepting a handoff the producer would reject is a hardening hole.
- Verify the producer's write order vs. ExitBootServices: is the memory map captured, then `BootHandoffV1` populated, with the final map key matched at `ExitBootServices`? Identify any window where the map can change after capture (`handoff/exit/`, `handoff/jump/`, `handoff/prepare/`).
- Trace `cmdline_ptr` lifetime: the kernel reads it as `&'static`; prove the pointed-to memory survives ExitBootServices and is in a kernel-mapped/owned range.
- Trace `entry_point`, framebuffer `ptr`, `acpi.rsdp`, `mmap.ptr`: prove every pointer the kernel dereferences is in a range still mapped after the bootloader's identity/directmap teardown sequence.

Deliverable: **ABI Equivalence Table** + a list of every divergence with severity.

### W2 — Duplicate / dead-code adjudication

For each candidate tree in §2: determine the live path from `main.rs`/`entry/` by call-graph, mark the rest dead or parallel, and recommend delete-or-merge with the risk of each. Quantify (LOC removed, modules collapsed). A "best version" cannot carry three keystores.

### W3 — Gap analysis

Enumerate: `todo!`/`unimplemented!`/`unreachable!`/`panic!` on reachable paths; `unwrap`/`expect` on attacker- or firmware-influenced data; `Result` swallowed into `Ok`/default; security checks gated behind `dev-mode`/`mock-proof` that could ship enabled; any verify→use TOCTOU (hash/verify a buffer, then re-read it). Cross-check feature flags in `nonos-bootloader/Cargo.toml` (`hardened`, `production`, `zk-vk-provisioned`, `mock-proof`) — prove `production`/`hardened-production` cannot select `mock-proof` or skip signature/ZK verification.

### W4 — Optimization

Oversized modules vs. the project's single-responsibility norm; the kernel image hashed/copied more than once; allocations after `ExitBootServices` or in interrupt-sensitive windows; redundant hardware re-enumeration (`hardware/`, `firmware/`, `security/hardware/` overlap); blocking delays on the critical boot path. Report cost, not just presence.

### W5 — Hardening

Threat model: malicious firmware tables (ACPI/SMBIOS/MADT/RSDP), malicious GOP/framebuffer geometry, malicious or rolled-back kernel image, malicious NVRAM/config, weak entropy, downgrade attacks. For each: where untrusted input enters, what bounds/sanity checks exist, what's missing. Specifically audit:

- Signature + ZK verification order vs. parse: is the kernel ELF parsed before its signature is checked? (parse-before-verify is an attack surface — `loader/`, `kernel_verify/`, `image_format/`, `crypto/signature/`).
- ELF loader bounds: segment overlap, p_offset/p_filesz/p_memsz overflow, entry-in-range, zero-tail (`loader/core/exec/`, `loader/segment/`, `loader/validate/`).
- Anti-rollback: is the NVRAM monotonic counter actually enforced before handoff, and resistant to NVRAM wipe (`security/anti_rollback/`)?
- Measured boot: which PCRs are extended with what, and is the chain complete from firmware to kernel entry (`security/tpm_extend/`, `security/attestation/`, `hardware/tpm/`)?
- Secret zeroization: are seeds/keys/buffers zeroized on every path including error/panic (`security/memory/zeroize/`, `entropy/wipe/`, `zk/transcript/wipe`)? Confirm `zk-zeroize`/`zeroize` is not optional in hardened profiles.
- Paging handoff: W^X on kernel text/data mapping, no stray identity mappings left writable+executable, identity window sized exactly to firmware load reality not guesswork (`paging/`, `handoff/jump/`).
- Boot UI as attack surface (§W6 overlaps): no untrusted-length/encoding data rendered without bounds.

### W6 — Boot UI design & hardening

The user wants the GUI to be a "best version" and hardened. Assess `display/`, `menu/`, `ui/`, `boot/vga/`:

- Design quality: layout system, theme, font rendering, log panel, progress/stage feedback, brand. Identify what's missing for a polished, deterministic boot experience (consistent stages, legible failure states, no flicker, no partial frames).
- Hardening: keyboard/input handling in `menu/input/` (no unbounded reads, timeout on prompts), GOP draw bounds (`display/gop/`, `display/font/draw.rs`), no rendering of attacker-controlled strings (firmware vendor strings, cmdline) without sanitization/length caps. The boot menu must fail closed: a timeout or invalid input must not select a less-verified boot path.

Propose a concrete UI design direction (states, layout grid, color/role semantics, failure UX) consistent with the existing constants in `display/constants/`.

## 5. Methodology rules

- Evidence first. Every finding: `path:line`, what you observed, why it matters, severity.
- Severity scale: **S0** breaks boot or the kernel contract; **S1** exploitable trust bypass; **S2** weakened guarantee / silent fallback; **S3** correctness/robustness; **S4** optimization/cleanliness.
- Prefer host tests (`host-tests` feature) or `offset_of`/`size_of` static reasoning over assertion for ABI claims.
- When two implementations conflict, determine the live one by call graph from `main.rs`, not by name.
- Distinguish *defense in depth* (intentional redundancy — keep) from *duplication* (drift risk — merge). Justify the call.
- Match house style: no comments, tight single-responsibility modules, self-explanatory names. Any proposed code obeys this.

## 6. Deliverables

1. **Findings Register** — table: ID, workstream, severity, `path:line`, claim, evidence, recommended fix, effort.
2. **ABI Equivalence Table** — every `BootHandoffV1` field/constant/flag, both sides, offsets, verdict (MATCH / DRIFT / UNVERIFIED), with the single authoritative-contract recommendation (ideally: extract one shared `#[repr(C)]` definition both crates import).
3. **Dedup Plan** — per candidate tree: live path, delete/merge recommendation, LOC delta, risk.
4. **Hardening Backlog** — ordered by severity, each with the threat it closes.
5. **Boot UI Direction** — one-page concrete design + the hardening fixes for the UI path.
6. **Prioritized Roadmap** — S0/S1 first, sequenced so the kernel contract is locked before cosmetic or dedup work; call out anything that must land before the user resumes kernel work.

## 7. Acceptance criteria

- No S0/S1 claim is **UNVERIFIED**: each is proven by test, static layout reasoning, or a cited code path.
- The ABI table is complete (every field, every nested struct, every constant) — no "looks the same."
- Every duplicate-tree recommendation names the live path with call-graph evidence.
- The roadmap explicitly identifies what blocks safe kernel↔bootloader handoff today.

## 8. Skills — mandatory

This investigation runs under the superpowers skill discipline. Invoke the skill **before** the corresponding work, announce it (`Using [skill] to [purpose]`), and follow it exactly. If a skill has a checklist, create one TodoWrite item per step.

- `superpowers:using-superpowers` — at the start; establishes the skill-first discipline for the whole audit.
- `superpowers:systematic-debugging` — before explaining any ABI drift, boot fault, or unexpected behavior (W1, the ExitBootServices/identity-teardown `#PF` surface). No fix proposed before root cause is proven.
- `superpowers:verification-before-completion` — before any finding is marked verified and before claiming the audit complete. Directly enforces §7: no S0/S1 may rest on assertion; show the test output or layout derivation.
- `superpowers:test-driven-development` — when producing the ABI equivalence proof and any fix: write the `host-tests` / `offset_of`+`size_of` static-assertion test first, watch it fail against current drift, then close it.
- `superpowers:writing-plans` — when producing the Prioritized Roadmap (§6.6) and Dedup Plan (§6.3); the roadmap is a written plan, not prose.
- `superpowers:brainstorming` — before W6 boot-UI design work (creative; explore intent and failure-UX options before proposing a direction).
- `simplify` — drives W2 dedup adjudication: review the parallel trees for reuse/quality and justify keep-vs-merge with evidence.
- `code-review:code-review` / `superpowers:requesting-code-review` — when any fix lands, before it is considered done.

Skill priority when several apply: **process skills first** (systematic-debugging, brainstorming) decide *how* to approach; **implementation skills second** (TDD, simplify) guide execution. User instructions and house style (no comments, tight single-responsibility modules) outrank any skill where they conflict.
