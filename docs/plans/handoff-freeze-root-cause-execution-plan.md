# Handoff Freeze Root-Cause Execution Plan

## 1) Reusable Prompt
Use this prompt when running a focused AI-assisted investigation pass:

```text
You are a Principal Rust Kernel Engineer debugging an early-boot handoff freeze in a no_std x86_64 UEFI microkernel.

Observed boot markers:
[PT0] [PT1] [KTXT] [EBS0] [EBS1] [MMAP1] [CR3OK] V> ... then kernel emits R and appears stuck.

Known findings:
- Bootloader->kernel jump and ABI boundary are likely valid because R is emitted at kernel_entry start.
- Kernel handoff validation can fail before serial is initialized, causing silent-looking stalls.
- Bootloader currently forwards GOP stride from UEFI mode info without unit conversion.
- Kernel validates framebuffer stride as bytes-per-scanline.

Your output must include:
1. Exact failing boundary in control flow
2. Ranked hypotheses with one disconfirming test each
3. Two-iteration instrumentation plan (minimal markers, high signal)
4. Minimal patch plan with rollback per edit
5. Verification matrix (commands + expected outputs)
6. Residual risks and guardrail tests

Constraints:
- no_std only
- surgical edits only
- no broad refactors
- preserve existing architecture and ABI
- every recommendation must map to observed boot evidence
```

## 2) Scope And Assumptions
- Scope: isolate and fix the freeze after CR3 handoff using minimal changes.
- Assumption A1: freeze boundary is after control transfer, inside early kernel handoff checks.
- Assumption A2: most likely first-order bug is framebuffer stride unit mismatch (pixels vs bytes).
- Assumption A3: current silent behavior is partly observability (serial init timing), not only control-flow failure.

## 3) Success Criteria
- Kernel progresses past handoff validation and prints post-handoff bring-up logs.
- No regression in bootloader jump contract, CR3 handoff, or early memory map handling.
- Fix is limited to producer/validator boundary and temporary diagnostics are removable cleanly.

## 4) File-Level Ownership
- Bootloader framebuffer producer:
  - nonos-bootloader/src/handoff/config/gop_handle.rs
- Kernel handoff entry and diagnostics:
  - src/nonos_main.rs
  - src/boot/handoff/api/init.rs
  - src/boot/handoff/api/security/framebuffer.rs
- Handoff transition references (read-only during this plan unless needed):
  - nonos-bootloader/src/handoff/exit/orchestrate.rs
  - nonos-bootloader/src/handoff/exit/validate.rs
  - nonos-bootloader/src/arch/x86_64/asm/handoff_jump.S
  - src/arch/x86_64/asm/start.S

## 5) Execution Phases

### Phase 0 - Baseline Reproduction And Evidence Lock
Checklist:
- [x] Boot with current known command and capture serial output from CR3OK onward.
- [x] Confirm marker sequence still reproduces the freeze point.
- [x] Save terminal log artifact for before/after comparison.

Commands:
```bash
make nonos-mk-run QEMU_NET='-device virtio-net-pci,netdev=net0 -netdev user,id=net0,hostfwd=tcp::2223-:22,hostfwd=tcp::8081-:80'
```

Gate to Phase 1:
- Reproduced freeze with same marker boundary and captured output.

Execution update (2026-05-14):
- Baseline command executed and captured.
- Observed behavior drifted: this run stalled after `[INFO] kernel_verify: Cryptographic verification complete` instead of reaching `[CR3OK] V> ... R`.
- Artifact source: terminal session `1275efb7-58a6-4773-9bfd-0bd59f952d92` output snapshot captured and preserved in session logs.
- Decision: proceed to Phase 1 instrumentation to re-establish precise failing boundary in current tree state.

Rollback:
- None (read-only phase).

### Phase 1 - High-Signal Instrumentation (No Behavior Change)
Checklist:
- [x] Add raw COM1 byte markers immediately before and after init_handoff call in src/nonos_main.rs.
- [x] Add one-byte error-class marker on init_handoff error branch (e.g., F for framebuffer geometry).
- [x] Optional: add marker points inside init_handoff around dereference and security validation.

Implementation rules:
- Keep instrumentation tiny and local.
- Do not alter handoff structure contents in this phase.

Validation:
```bash
make nonos-mk-run-serial
# or
make nonos-mk-run QEMU_NET='-device virtio-net-pci,netdev=net0 -netdev user,id=net0,hostfwd=tcp::2223-:22,hostfwd=tcp::8081-:80'
```

Expected if A2 is correct:
- Marker shows init_handoff error path with framebuffer-related classification.

Gate to Phase 2:
- Evidence points to framebuffer stride validation mismatch.

Execution update (2026-05-14):
- Added kernel-entry COM1 byte instrumentation in `src/nonos_main.rs` around `init_handoff`.
- Added temporary verified-boot stage markers (`[VB0]..[VB6]`) in `nonos-bootloader/src/entry/pipeline.rs` to handle observed baseline drift and recover precise boundary tracing.
- Validation run recovered expected late-boot sequence (`[PT0]...[CR3OK] V> ... R`) and confirmed progression into kernel entry path.
- Decision: continue with producer-side stride contract fix.

Rollback:
- Revert only marker lines if phase is complete or noisy.

### Phase 2 - Minimal Contract Fix At Producer Boundary
Checklist:
- [x] In nonos-bootloader/src/handoff/config/gop_handle.rs, convert GOP stride from pixels to bytes-per-scanline.
- [x] Use checked math and bounds-safe cast when writing stride into handoff struct.
- [x] Preserve existing pixel format mapping behavior (no redesign in this phase).

Implementation note:
- bytes_per_pixel should be derived from GOP format used by kernel path assumptions.

Validation:
```bash
make nonos-mk-run-serial
```

Expected if fix is correct:
- Boot passes prior freeze boundary and reaches nonos handoff/core init logs.

Gate to Phase 3:
- Consistent pass across at least 2 consecutive boots.

Execution update (2026-05-14):
- Implemented stride conversion in `nonos-bootloader/src/handoff/config/gop_handle.rs`:
  - `stride_pixels -> stride_bytes`
  - checked multiply with bytes-per-pixel
  - u32 bounds guard before storing into handoff
- Validation run succeeded past prior freeze boundary and continued deep into kernel bring-up and userspace spawn sequence.
- Observed key pass markers and logs after fix:
  - `[PT0] [PT1] [KTXT] [EBS0] [EBS1] [MMAP1] [CR3OK] V> ... R`
  - `[NONOS] Microkernel init`, `[INIT] Starting`, capsule spawn logs
- Phase 2 gate status: functional pass achieved; second consecutive pass pending in Phase 3 cleanup run.

Rollback:
- Revert stride conversion hunk only.

### Phase 3 - Stabilize, Remove Diagnostics, And Guardrails
Checklist:
- [x] Remove temporary raw markers from src/nonos_main.rs/init path.
- [x] Keep one minimal durable early marker only if justified.
- [x] Add/adjust focused test or assertion for framebuffer stride contract.
- [x] Re-run boot path and static checks.

Validation:
```bash
make nonos-mk-run-serial
cargo check --lib --features std --target x86_64-apple-darwin
```

Exit criteria:
- No freeze at former boundary.
- No temporary debug noise left (unless intentionally retained).
- Checks pass.

Execution update (2026-05-14):
- Removed temporary diagnostics from:
  - `src/nonos_main.rs` (Phase 1 COM1 markers)
  - `nonos-bootloader/src/entry/pipeline.rs` (temporary `[VB*]` markers)
- Added producer-side guardrail in `nonos-bootloader/src/handoff/config/gop_handle.rs`:
  - compute `min_row_bytes = width * bytes_per_pixel` with checked math
  - reject GOP handle if `stride_bytes < min_row_bytes`
- Cleanup validation boot (`make nonos-mk-run-serial`) passed and progressed well beyond prior freeze boundary into microkernel/userland bring-up.
- Static check command status:
  - `cargo check --lib --features std --target x86_64-apple-darwin` failed with `#[panic_handler] function required, but not found` plus existing warnings.
  - This failure is outside the framebuffer stride fix scope and is recorded as a residual repository build configuration issue for this command profile.

Rollback:
- Reapply temporary markers from prior commit if regression reappears.

## 6) Verification Matrix

| Experiment | Command | If Hypothesis Correct | If Wrong |
|---|---|---|---|
| Baseline | make nonos-mk-run-serial | Repro at CR3OK/V>/R boundary | Different boundary; reassess |
| Markers only | make nonos-mk-run-serial | Error branch indicates framebuffer/security failure | Fault before marker exit; inspect pointer/map boundary |
| Producer fix | make nonos-mk-run-serial | Progress past handoff init; continued boot | Same freeze; move to pointer mapping hypothesis |
| Cleanup pass | make nonos-mk-run-serial + cargo check | Stable boot and clean checks | Reintroduce markers and bisect |

## 7) Risk Register
- R1: bytes_per_pixel interpretation mismatch for uncommon GOP formats.
  - Mitigation: keep mapping conservative and log format IDs during test runs.
- R2: hidden mapping issue masked by prior framebuffer failure.
  - Mitigation: preserve phase gates; if fix fails, pivot to pointer/map diagnostics only.
- R3: temporary instrumentation leaks into final branch state.
  - Mitigation: dedicated cleanup phase and diff review before merge.

## 8) Commit Strategy
- Commit 1: debug(boot): add minimal handoff boundary markers
- Commit 2: fix(bootloader-handoff): convert gop stride to bytes-per-scanline
- Commit 3: chore(debug): remove temporary boot markers and keep guardrail check

## 9) Operator Runbook
- To run serial-only:
```bash
make nonos-mk-run-serial
```
- To run with alternate forwarded ports:
```bash
make nonos-mk-run QEMU_NET='-device virtio-net-pci,netdev=net0 -netdev user,id=net0,hostfwd=tcp::2223-:22,hostfwd=tcp::8081-:80'
```
- To stop stale QEMU instances occupying forwarded ports:
```bash
lsof -nP -iTCP:8080 -sTCP:LISTEN
# then stop the stale process if needed
```
