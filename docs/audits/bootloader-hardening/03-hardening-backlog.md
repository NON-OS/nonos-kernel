# Bootloader Hardening Backlog (W5)

Ordered S0 -> S4. Each item names the threat it closes, the attacker input that
triggers it, the invariant restored, a one-line fix direction, effort, and the
matching `W5-NN` row in `01-findings-register.md`. The register rows are the
canonical findings; this file is the ordered narrative. W3/W4 rows are untouched.

"S0 -> S4" is the scale, not a guarantee of occupancy: W5 produced no S0
(no boot/contract-breaker in scope) and no S4 (cleanliness items were W3/W4),
so this file contains only S1–S3 plus the kernel cross-ref W5-CR1. The
consolidated cross-workstream tally and scoring-granularity note live in
`01-findings-register.md`, which is the single source of record.

Live spine reused and re-verified (not blindly trusted): `efi_main` (main.rs:28)
-> `boot_entry` (entry/boot.rs:24) -> `run_security_checks` (boot/security/run.rs:28,
which calls `init_anti_rollback` via `init_subsystems` boot/security/platform.rs:35)
-> `run_verified_boot` (entry/pipeline.rs:28) -> `run_kernel_load` ->
`run_crypto_verification` (pipeline.rs:36, parses footer + verifies signature) ->
`run_zk_attestation` (pipeline.rs:37, kernel->PCR9 extend on the verified+proof path)
-> `run_elf_parse` (pipeline.rs:46, the ELF itself is parsed/loaded HERE) ->
`commit_rollback` (pipeline.rs:47) -> `run_handoff_prepare` (pipeline.rs:49) ->
`exit_and_jump` (handoff/exit/orchestrate.rs:32): `build_kernel_pml4` ->
`secure_cleanup_before_jump` (orchestrate.rs:84) -> `exit_boot_services`
(orchestrate.rs:87) -> `switch_to_kernel_pml4` (orchestrate.rs:98) -> jump.

DEAD on the live `load_kernel` path (do NOT confuse with the live loader):
`loader/validate/` (the `validate_elf_strict`/`WxViolation`/`checked_add` tree)
and `loader/segment/` are NOT reached by `load_kernel` (loader/core/load.rs:32),
which uses `loader/core/elf_validate.rs` + `loader/core/segment_check.rs`
(goblin-based). `loader/validate/` is referenced only by `loader/mod.rs`
re-exports and the also-dead `loader/security/`. Hardening claims below are
scored against the LIVE goblin loader, not the stricter dead tree.

Parse-before-verify verdict: VERIFY-THEN-PARSE for the ELF. The kernel ELF body
is parsed/loaded by `load_kernel` only inside `run_elf_parse` (pipeline.rs:46),
which runs AFTER Ed25519 signature verification in `run_crypto_verification`
(pipeline.rs:36). The footer IS parsed before verification (`parse_image_footer`
via `validate_image`, kernel_verify/verify.rs:48) but only to LOCATE the byte
range to hash/verify; that parser is fully bounds-checked (image_format/parse/
parsed.rs:33-100, checked offsets, `total_image_size == file_len`, no-overlap).
This is parse-to-locate, not parse-the-trusted-structure-before-verifying, so it
is NOT an S0/S1 parse-before-verify violation. The residual issue is that the
footer fields that are parsed are themselves OUTSIDE the signed region (W5-09).

---

## S1

### W5-09 — Anti-rollback floor downgradable via an unsigned footer field
- Threat closed: rollback-attack via footer tamper without breaking the signature.
- Attacker input: a validly-signed kernel image whose footer `image_version`
  (offset 48..52, image_format/parse/bytes.rs:45) is lowered. Ed25519 covers only
  `parsed.kernel_bytes` (crypto/verify/bytes.rs:33; kernel_verify/signature.rs:43
  passes `kernel_code` = the kernel slice). The footer is never in the signed
  message, yet `check_rollback`/`commit_rollback` (boot/crypto/rollback.rs:31,49)
  read `parsed.footer.image_version` to drive the monotonic-version decision.
- Invariant restored: the value that gates anti-rollback must be authenticated by
  the same signature that authenticates the kernel.
- Fix direction: include the footer (or at minimum `image_version`) in the signed
  message, or carry the rollback version inside the signed kernel payload.
- Effort: M. Register: W5-09.

### W5-12 — Firmware ACPI/SMBIOS pointer handed to kernel with zero validation
- Threat closed: malicious/quirky firmware config-table entry steering the kernel
  to dereference an attacker-chosen physical pointer as RSDP/SMBIOS.
- Attacker input: a UEFI configuration-table entry under `ACPI2_GUID`/`SMBIOS3_GUID`
  with an arbitrary `address`. `get_acpi_rsdp` (handoff/config/acpi.rs:21-28) and
  `get_smbios_entry` (handoff/config/smbios.rs:21-28) return `entry.address`
  verbatim — no `"RSD PTR "` signature check, no checksum, no range/bounds. The
  values are written into the handoff struct at gather.rs:31/33 and consumed by
  the kernel. The checksum-validating `discover_acpi_rsdp` (hardware/acpi/rsdp.rs)
  result is computed then discarded into `_hw` (W4-05), so the kernel gets the
  UNVALIDATED pointer.
- Invariant restored: a firmware-supplied pointer crossing the boot->kernel trust
  boundary must be signature/checksum/range validated before handoff.
- Fix direction: validate RSDP signature+checksum (reuse the existing rsdp.rs
  logic) and SMBIOS anchor before writing into the handoff struct; thread the
  already-validated `discover_acpi_rsdp` result instead of re-walking unchecked.
- Effort: M. Register: W5-12.

---

## S2

### W5-03 — Anti-rollback fails OPEN on a no-TPM / NVRAM-wiped platform
- Threat closed: rollback to an older signed kernel by removing/clearing TPM NVRAM.
- Attacker input: a platform with no TPM (or a wiped/garbled NVRAM version blob).
  `init_anti_rollback` (boot/security/platform.rs:35) is called with
  `tpm_available = security.measured_boot_active`. `AntiRollbackState::init`
  (security/anti_rollback/state/init.rs:22-33): with `tpm_available == false` it
  SKIPS the NVRAM read entirely and sets `initialized = true` over a zeroed
  `VersionState::new()` (minimum_kernel = 0). With TPM but `NvramReadFailed`
  (absent/garbage/hash-mismatch, nvram/read.rs:28/31) it silently resets to
  `VersionState::new()` (init.rs:27). Then `check_kernel_version`
  (state/check.rs:21-27): the `!initialized && !tpm_available` guard is false
  (initialized is true), `minimum_kernel == 0`, so any version >= 1 passes.
  Rollback enforcement is effectively absent off-TPM and after an NVRAM wipe.
- Invariant restored: anti-rollback must fail CLOSED — absence or loss of the
  monotonic counter must block boot under signature-requiring modes, not reset
  the floor to zero.
- Fix direction: treat no-TPM and `NvramReadFailed` as a hard rollback failure
  under `mode.requires_signature()` (mirror the W3-style `fatal_reset`), rather
  than initializing a zero floor.
- Effort: M. Register: W5-03.

### W5-10 — 64 GiB identity window is mapped RWX (no NX); kernel text aliased W+X
- Threat closed: a writable+executable alias of the entire low physical range
  (incl. kernel text/data, handoff, stack) surviving until the kernel tears it
  down; defeats the strict W^X the loader applies to the upper-half window.
- Attacker input / mechanism: `IDENTITY_LOW_BYTES = 0x10_0000_0000` (64 GiB,
  paging/constants.rs:43) is mapped by `map_identity_low` (paging/map_identity.rs:38)
  with `flags = PTE_RW` ONLY; `map_huge_1g_run` writes `phys | PTE_P | PTE_PS |
  flags` (paging/mapper/map_huge_1g_run.rs:63) so NO PTE_NX is set across all 64
  1-GiB pages. The directmap correctly adds `PTE_NX` (paging/map_directmap.rs:29),
  proving NX was intentionally chosen there and omitted here. Every kernel
  PT_LOAD that `map_kernel_text` carefully mapped W^X (paging/seg_flags.rs:33,
  rejects W+X / sets NX) is simultaneously reachable RWX through the identity
  alias at its physical address until kernel `clear_low_half()` runs.
- Invariant restored: no region the bootloader leaves mapped at handoff should be
  simultaneously writable and executable.
- Fix direction: split the identity window — executable-needed range (bootloader
  trampoline code only) without PTE_RW, the remainder with PTE_NX; or shrink the
  window to the minimum that keeps the post-CR3 RIP + handoff/stack reachable.
- Effort: M. Register: W5-10.

### W5-05 — Pre-jump secret wipe is a placebo for the ZK transcript and entropy pool
- Threat closed: ZK Fiat-Shamir transcript state and the boot entropy seed
  remaining in RAM, readable by the kernel/next stage after handoff.
- Attacker input: not externally triggered; this is a missing-wipe on EVERY path
  (the call is unconditional on the live spine). `secure_cleanup_before_jump`
  (handoff/exit/cleanup.rs:20) -> `wipe_zk_state` -> `wipe_transcript`
  (zk/transcript/wipe.rs:17-19) is ONLY a `compiler_fence` — it zeroes nothing.
  -> `wipe_entropy_pools` -> `wipe_entropy_state` -> `wipe_entropy_pool`
  (entropy/core.rs:68-70) is ALSO only a `compiler_fence`. The real `zeroize_*`
  primitives (security/memory/zeroize/core.rs:21-42, correct `write_volatile` +
  fence) are NOT invoked here. The persisted `BOOT_NONCE`
  (zk/binding/replay/nonce.rs:21, a `static Mutex<Option<[u8;32]>>`) is never
  wiped by any path. Contrast: `wipe_signing_state` (crypto/sig.rs:33-40) IS real.
- Invariant restored: every secret/seed/transcript buffer is volatile-zeroed on
  the path to handoff (and on error/early-return), not merely fenced.
- Fix direction: make `wipe_transcript` and `wipe_entropy_pool` zero their backing
  state with the `zeroize_*` primitives, and zero `BOOT_NONCE`, before EBS.
- Effort: S. Register: W5-05.

### W5-06 — `zeroize`/`zk-zeroize` is optional and absent from hardened/production
- Threat closed: a shipped hardened/production artifact silently compiling out ZK
  proof zeroization.
- Attacker input: build configuration, not runtime. Cargo.toml:57 `zeroize` is
  `optional = true`; Cargo.toml:95 `zk-zeroize = ["zeroize"]`; Cargo.toml:69
  `default` includes `zk-zeroize`, but `hardened` (73), `production` (77),
  `hardened-production` (78) do NOT pull `zk-zeroize`/`zeroize`. The only
  consumer, `zeroize_proof` (zk/verify/util.rs:28), has a
  `#[cfg(not(feature="zk-zeroize"))]` no-op stub (util.rs:38-39). A
  `--no-default-features --features hardened-production` build ships with proof
  zeroization compiled out. (Same build-profile ambiguity as W3 UNVERIFIED-1.)
- Invariant restored: zeroization of proof/secret material must be non-optional
  in any profile claiming "hardened"/"production".
- Fix direction: have `hardened`/`production`/`hardened-production` transitively
  require `zk-zeroize` (and `zeroize`), or make `zeroize_proof` unconditional.
- Effort: S. Register: W5-06.

### W5-07 — Measured-boot chain has gaps (PCR8 measures a constant; PCR9 skipped
without a ZK proof; signature field zeroed)
- Threat closed: TPM attestation that does not actually bind the loaded
  bootloader/kernel/signature.
- Attacker input / mechanism: (a) PCR8 (PCR_BOOTLOADER) is extended only with the
  fixed probe string `b"NONOS:TPM:PROBE:v1"` (security/check/tpm.rs:22-23) — it
  measures a constant, not the bootloader image; the real
  `measure_boot_components` (security/tpm_extend/components.rs:23) has no live
  caller. (b) The real kernel measurement `extend_boot_measurements`
  (security/enforce/checks/measurements.rs:21) is invoked only from
  `display_success` (boot/attestation/run/success.rs:38) on the
  ZK-proof-present-AND-verified path; `run_zk_attestation` returns via
  `handle_no_proof` for any image without a ZK proof
  (boot/attestation/run/orchestrate.rs:31), so PCR9 is NEVER extended for a
  no-ZK-proof kernel. (c) Even on the measured path the `signature` argument is
  hardcoded `[0u8;64]` (success.rs:37), so the signature is not measured. The
  extend that does happen is correctly ordered before handoff (pipeline.rs:37
  before :49).
- Invariant restored: a gap-free firmware->kernel measurement: bootloader image
  into PCR8, kernel+signature into PCR9 on every boot regardless of ZK presence.
- Fix direction: measure the actual bootloader bytes into PCR8 unconditionally;
  extend PCR9 with the real kernel hash + real signature on every path, not only
  the ZK-verified branch.
- Effort: M. Register: W5-07.

---

## S3

### W5-02 — Live goblin loader has no PT_LOAD overlap check
- Threat closed: a malformed signed ELF whose two PT_LOADs resolve to the same
  physical destination, letting a later segment clobber an earlier one
  post-staging (parser-differential vs. the signer's intent).
- Attacker input: a signed kernel ELF with overlapping PT_LOAD
  `[p_vaddr, p_vaddr+p_memsz)` ranges. The live path
  (`validate_segments`, loader/core/elf_validate.rs:111-151;
  `validate_single_segment`, loader/core/segment_check.rs) checks per-segment
  `p_memsz >= p_filesz` (segment_check.rs:36), `p_offset+p_filesz` overflow
  (segment_check.rs:44, `checked_add`), `seg_end` overflow
  (segment_check.rs:104, `checked_add`), `file_end <= payload.len()`
  (segment_check.rs:52), and entry-in-range (loader/core/exec/entry_in_range.rs
  via load_exec_kernel.rs:74) — but NO pairwise segment-overlap check. The
  overlap checker that exists (image_format/parse/overlap.rs and the dead
  `loader/validate/`) does not run on this path. `load_segments`
  (loader/core/exec/load_segments.rs:49,66) computes `dst_phys = phys_base +
  (virt - virt_min)` and `copy_payload`s with no overlap guard.
- Invariant restored: distinct PT_LOAD segments map to disjoint
  physical/virtual ranges (defense-in-depth; the image is signature-verified
  before this runs, so exploitability requires a signer mistake or a parser
  differential, hence S3 not S1).
- Fix direction: add a pairwise `[virt, virt+memsz)` overlap rejection in
  `validate_segments` (port the `image_format/parse/overlap.rs` logic).
- Effort: S. Register: W5-02.

### W5-08 — Loader staging table (16) smaller than validation cap (32);
segments 16..31 copied to phys but dropped from the paging layout
- Threat closed: a high-PT_LOAD-count signed ELF whose tail segments are written
  into physical memory but never mapped, yielding an inconsistent kernel image.
- Attacker input: a signed ELF with 17..32 PT_LOAD segments. `validate_segments`
  accepts up to `MAX_LOADS = 32` (loader/core/elf_validate.rs:126, loader/core/
  constants.rs:18). `load_segments` (loader/core/exec/load_segments.rs) runs the
  `copy_payload`/`zero_tail` for ALL of them (lines 65-76, unconditional) but
  only records the first `MAX_KERNEL_SEGMENTS = 16`
  (loader/image/segment_layout.rs:30) into the layout array, dropping the rest
  with a `log_warn` (load_segments.rs:88-101). Paging
  (paging/map_kernel_text.rs:42) then maps only the recorded 16, so segments
  16..31 are present in RAM but unmapped (or only RWX-identity-aliased, see
  W5-10).
- Invariant restored: the validation cap, the staging-table size, and the paging
  layout size must agree; a segment that is staged must be mapped, or the image
  must be rejected.
- Fix direction: make `MAX_KERNEL_SEGMENTS == MAX_LOADS` (or reject when
  `load_count > MAX_KERNEL_SEGMENTS` instead of silently dropping).
- Effort: S. Register: W5-08.

### W5-11 — GOP geometry: stride not cross-checked against width / fb_size
- Threat closed: firmware/GOP reporting a `stride < width*4` or a
  `width*height*4 > fb_size`, leading the kernel to compute a framebuffer extent
  inconsistent with the actual mapping.
- Attacker input: a GOP mode whose `stride_pixels`/resolution/`fb.size()` are
  mutually inconsistent. `try_gop_handle` (handoff/config/gop_handle.rs:27-46)
  rejects zero width/height/stride/ptr/size and guards `stride.checked_mul`
  (line 34, overflow-safe) — good — but never checks `stride >= width*4` nor
  `stride * height <= fb_size`. The kernel consumes these as a trusted geometry.
- Invariant restored: reported framebuffer geometry must be internally
  consistent before crossing the trust boundary.
- Fix direction: in `try_gop_handle`, reject when `stride < width *
  size_of::<u32>()` or `stride as u64 * height as u64 > fb_size`.
- Effort: S. Register: W5-11.

---

## Cross-reference (KERNEL-side; recorded, NOT patched per audit charter)

### W5-CR1 — LAPIC EOI #PF at cr2=0xFEE000B0 after identity-map teardown
- Classification: KERNEL-side root cause. Bootloader paging is correct here; the
  fix belongs to kernel LAPIC addressing, out of scope for bootloader patching.
- Proven mechanism (from bytes/offsets, no live repro needed):
  1. `LOCAL_APIC_DEFAULT_BASE = 0xFEE0_0000` (src/sys/apic/local.rs:20);
     `LAPIC_EOI = 0x0B0` (local.rs:25). `eoi()` does
     `lapic_write(LAPIC_EOI, 0)` (local.rs:96-100).
  2. `lapic_write` computes `(base + reg) as *mut u32` and
     `write_volatile`s it (local.rs:50-55) — a RAW PHYSICAL address
     `0xFEE00000 + 0xB0 = 0xFEE000B0`, exactly the recorded cr2. No directmap
     translation, no ioremap.
  3. The bootloader PML4 reaches raw phys `0xFEE000B0` ONLY via the low identity
     map (PML4[0], paging/map_identity.rs:38). The directmap (PML4[256],
     paging/map_directmap.rs:29) places that phys at
     `DIRECTMAP_BASE + 0xFEE00000`, NOT at raw `0xFEE00000`; kernel-text
     (PML4[511]) does not cover it either.
  4. Kernel `init_unified_vm` Step 6 (src/memory/unified/init/run.rs:87-96):
     when `kernel_half_populated >= 2` (directmap + kernel-text, i.e. the
     upper-half NoNOS layout) it calls `clear_low_half()` — dropping PML4[0].
  5. Any LAPIC access after Step 6 (`eoi`, `lapic_read/write`) dereferences raw
     `0xFEE000B0`, now unmapped -> #PF, cr2=0xFEE000B0. Falsifier: if
     `LAPIC_BASE` were a directmap/ioremap virt that survives Step 6, or if the
     identity were not torn down, the fault would not occur.
- Bootloader-side note: the bootloader deliberately does NOT leave an LAPIC
  mapping in the surviving PML4[256..511]; that is by design (the kernel owns
  its MMIO mappings post-handoff). The bootloader contract is sound.
- Recommended direction (kernel team, sequencing only — DO NOT patch here):
  map the LAPIC MMIO page into a window that survives identity teardown (e.g.
  set `LAPIC_BASE` to `phys_to_virt(0xFEE00000)` in the directmap, or establish
  an explicit ioremap/UC mapping) BEFORE any post-Step-6 LAPIC access; or defer
  `clear_low_half()` until LAPIC has been re-based. Register: W5-CR1.

## UNVERIFIED (W5)

See the `UNVERIFIED (W5)` subsection in `01-findings-register.md`.
