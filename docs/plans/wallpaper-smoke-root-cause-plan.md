# Wallpaper Smoke Root-Cause Plan

Status: in-progress
Date: 2026-05-12
Scope: find why wallpaper serial markers are not emitted during smoke boot

## Problem Statement

Current smoke harness fails with:
- `[wallpaper-smoke] FAIL: wallpaper launch path not reached`

Meaning: the run did not produce the expected kernel launch marker line before timeout. This is a runtime-path issue, not a compile failure.

## Ranked Hypotheses

1. Boot does not reach userspace init (`run_init`) within harness timeout.
2. Userspace init runs, but wallpaper smoke branch is not active at runtime (feature/profile mismatch).
3. Wallpaper launch path executes but serial marker is not visible in current QEMU serial mode.
4. Wallpaper seed/exec precondition fails before marker emission.
5. `exec_process` fails after launch call, and failure is not yet visible early enough in logs.

## Investigation Rules

1. Do not widen scope beyond wallpaper smoke path.
2. Keep changes surgical and reversible.
3. One diagnosis patch at a time, one rerun after each patch.
4. Keep marker text exact and stable.

## Execution Checklist (Global)

Run this before each phase:

- [x] Working tree state captured (`git status --short`)
- [x] Last command output path captured
- [x] Current harness timeout value recorded
- [x] Exact kernel profile used recorded
- [x] One run = one evidence bundle (no mixed logs)

Evidence bundle template:

- run_id:
- commit:
- command:
- exit_code:
- log_path:
- first_failure_line:
- decision:

## Phase 0: Reproducible Evidence Capture

Goal: collect one canonical log per run.

Commands:
1. `./nonos-ci/wallpaper_round_trip.sh`
2. Save full serial log artifact path from the tool output.

Exit condition:
- One complete log with harness failure line and final QEMU termination context.

Checklist:

- [x] Run completed with non-empty log
- [x] Harness FAIL line present
- [x] Final 120 lines saved for triage
- [x] Marker search command output saved
- [x] Evidence bundle filled

Commands (exact):

1. `./nonos-ci/wallpaper_round_trip.sh`
2. `tail -n 120 <LOG_PATH>`
3. `rg -n "\[wallpaper-smoke\]|\[NONOS\] wallpaper|\[wallpaper\]|INIT-TRACE|FAIL" <LOG_PATH>`

Stop conditions:

- [ ] Harness script parse error
- [ ] No log artifact path available

## Phase 1: Boot Progression Boundary

Goal: locate first missing stage in boot timeline.

Check for existing markers in log, in this order:
1. `[INIT-TRACE] before firmware`
2. `[INIT-TRACE] after process-management`
3. `[INIT-TRACE] before spawn_ramfs_capsule`
4. `[INIT-TRACE] before spawn_proof_io_capsule` (when proof profile is enabled)
5. `[NONOS] wallpaper: launching from /capsules/wallpaper`

Decision:
- If none of the INIT markers appear: failure is pre-userspace-init.
- If INIT markers appear but wallpaper launch marker does not: failure is feature/branching or launch-path gating.

Checklist:

- [x] INIT marker 1 checked
- [x] INIT marker 2 checked
- [x] INIT marker 3 checked
- [x] INIT marker 4 checked (profile-dependent)
- [x] wallpaper launch marker checked
- [x] First missing marker identified
- [x] Decision recorded in evidence bundle

Gate:

- PASS to Phase 2 only when first missing stage is identified.

## Phase 2: Feature/Profile Fidelity

Goal: prove the kernel image being booted includes wallpaper smoke features.

Commands:
1. `rg -n "microkernel-wallpaper-smoketest|nonos-wallpaper-smoketest|nonos-capsule-wallpaper" Cargo.toml`
2. `make nonos-mk-wallpaper-test`
3. `strings target/x86_64-nonos/release/nonos-kernel | rg "wallpaper: launching from /capsules/wallpaper|capsules/wallpaper"`

Decision:
- If marker string is absent from image: wrong profile/image being booted.
- If present: runtime path is likely not reached.

Checklist:

- [x] Feature definitions found in Cargo
- [x] Wallpaper smoketest build command succeeds
- [x] `strings` contains wallpaper launch path marker
- [x] `strings` contains `/capsules/wallpaper`
- [x] Booted image path matches built image path

Additional checks:

1. `sha256sum target/x86_64-nonos/release/nonos-kernel`
2. Confirm ESP copy timestamp is newer than kernel build timestamp

- [x] Additional check 1 executed
- [x] Additional check 2 executed

Additional evidence (path fidelity):

1. `sha256sum target/kernel_attested.bin target/esp/EFI/nonos/kernel.bin` -> hashes match.
2. `cat target/esp/EFI/nonos/boot.cfg && cat target/esp/startup.nsh` -> boot path resolves through `fs0:\EFI\Boot\BOOTX64.EFI`, which loads `EFI/nonos/kernel.bin`.

Gate:

- If profile mismatch is proven, fix profile/packaging and rerun Phase 0.

## Execution Log (Live)

### Run R0 (Phase 0 + Phase 1)

- run_id: R0
- commit: working tree dirty (see `git status --short` snapshot)
- command: `./nonos-ci/wallpaper_round_trip.sh`
- exit_code: 1
- log_path: `/Users/abuhamzah/Library/Application Support/Code/User/workspaceStorage/72bea6bf1d304d70b44fe09ad84f016e/GitHub.copilot-chat/chat-session-resources/cf45b47b-dea6-4d66-a5b5-be8c8d8906b9/call_mBKwRvCInRm70CaZVMNdM1Qb__vscode-1778555433444/content.txt`
- first_failure_line: `[wallpaper-smoke] FAIL: wallpaper launch path not reached`
- decision: pre-userspace-init boundary (no INIT markers observed)

### Run R1 (Phase 2 fidelity)

- run_id: R1
- commit: same working tree
- command: `make nonos-mk-wallpaper-test`
- exit_code: 0
- log_path: `/Users/abuhamzah/Library/Application Support/Code/User/workspaceStorage/72bea6bf1d304d70b44fe09ad84f016e/GitHub.copilot-chat/chat-session-resources/cf45b47b-dea6-4d66-a5b5-be8c8d8906b9/call_OGvQPZfOW3oUztIsDBjIvjIH__vscode-1778555433455/content.txt`
- first_failure_line: none (build succeeded)
- decision: profile features compile and wallpaper launch strings are present in kernel image; runtime path still not reached during smoke run

### Run R2 (Phase 3 instrumentation)

- run_id: R2
- commit: same working tree + temporary `[WALLPAPER-RC]` markers
- command: `./nonos-ci/wallpaper_round_trip.sh`
- exit_code: 1
- log_path: `/Users/abuhamzah/Library/Application Support/Code/User/workspaceStorage/72bea6bf1d304d70b44fe09ad84f016e/GitHub.copilot-chat/chat-session-resources/cf45b47b-dea6-4d66-a5b5-be8c8d8906b9/call_iW36jfweK17xNFTPfHdRN6XN__vscode-1778555433464/content.txt`
- first_failure_line: `[wallpaper-smoke] FAIL: wallpaper launch path not reached`
- decision: no `[WALLPAPER-RC]` markers were emitted; failure remains pre-userspace-init

### Run R3 (live-stream + timeout diagnostics)

- run_id: R3
- commit: same working tree + live-streaming harness
- command: `./nonos-ci/wallpaper_round_trip.sh`
- exit_code: 1
- log_path: `/Users/abuhamzah/Library/Application Support/Code/User/workspaceStorage/72bea6bf1d304d70b44fe09ad84f016e/GitHub.copilot-chat/chat-session-resources/cf45b47b-dea6-4d66-a5b5-be8c8d8906b9/call_SxhW55NWJKkd3hBNKsJjOjyt__vscode-1778555433496/content.txt`
- first_failure_line: `[wallpaper-smoke] FAIL: wallpaper launch path not reached`
- decision: QEMU process remained alive for full timeout window (`boot rc=124`, `boot seconds=240`) with no runtime markers observed

### Run R4 (serial mode A/B: repo-standard)

- run_id: R4
- commit: same working tree + harness switched to `-serial mon:stdio -display none`
- command: `bash -n nonos-ci/wallpaper_round_trip.sh && ./nonos-ci/wallpaper_round_trip.sh`
- exit_code: 1
- log_path: `/Users/abuhamzah/Library/Application Support/Code/User/workspaceStorage/72bea6bf1d304d70b44fe09ad84f016e/GitHub.copilot-chat/chat-session-resources/cf45b47b-dea6-4d66-a5b5-be8c8d8906b9/call_Fu4ZqqkC1XeYOWpnrt7FmBJo__vscode-1778555433505/content.txt`
- first_failure_line: `[wallpaper-smoke] FAIL: wallpaper launch path not reached`
- decision: serial flag variant did not change boundary; still 240s timeout with no runtime markers

### Run R5 (artifact path fidelity)

- run_id: R5
- commit: same working tree
- command: `sha256sum target/kernel_attested.bin target/esp/EFI/nonos/kernel.bin && cat target/esp/EFI/nonos/boot.cfg && cat target/esp/startup.nsh`
- exit_code: 0
- log_path: in-terminal evidence (current session output)
- first_failure_line: none
- decision: boot payload fidelity confirmed (ESP kernel matches freshly built attested kernel)

### Run R6 (pre-kernel boundary proof via QEMU stdio/debug logs)

- run_id: R6
- commit: same working tree
- command: bounded QEMU boot with stdio + `/tmp/nonos-qemu-stdio.log` and `/tmp/nonos-qemu-debug.log`
- exit_code: timeout kill (expected for bounded probe)
- log_path: `/tmp/nonos-qemu-stdio.log`, `/tmp/nonos-qemu-debug.log`
- first_failure_line: none (diagnostic probe)
- decision: bootloader reaches `[INFO] kernel_verify: Cryptographic verification complete`, but no subsequent loader/handoff/kernel markers appear before timeout

### Run R7 (bootloader RC instrumentation build attempt)

- run_id: R7
- commit: same working tree + temporary bootloader `[WALLPAPER-RC]` markers around `verify_boot_attestation`
- command: `cd nonos-bootloader && cargo build --target x86_64-unknown-uefi --release --features "default,zk-snark,efi-rng,nonos-cet"`
- exit_code: 101
- log_path: in-terminal evidence (current session output)
- first_failure_line: compile error in `src/entropy/collector.rs`
- decision: bootloader marker rerun blocked until existing bootloader compile errors are resolved

### Run R8 (bootloader build unblock)

- run_id: R8
- commit: same working tree + entropy collector API fix
- command: `cd nonos-bootloader && cargo build --target x86_64-unknown-uefi --release --features "default,zk-snark,efi-rng,nonos-cet"`
- exit_code: 0
- log_path: in-terminal evidence (current session output)
- first_failure_line: none
- decision: bootloader rebuild unblocked; temporary bootloader RC marker binary is now buildable

### Run R9 (bounded probe with valid OVMF paths)

- run_id: R9
- commit: same working tree
- command: bounded QEMU boot with discovered OVMF files (`/usr/local/share/qemu/edk2-x86_64-code.fd`, `/usr/local/share/qemu/edk2-i386-vars.fd`) writing `/tmp/nonos-wallpaper-rc-zk.log`
- exit_code: bounded-run diagnostic (timeout window)
- log_path: `/tmp/nonos-wallpaper-rc-zk.log`
- first_failure_line: none (diagnostic probe)
- decision: output still ends at `[INFO] kernel_verify: Cryptographic verification complete`; no bootloader `[WALLPAPER-RC]` marker, no `handoff`, and no kernel markers observed

### Run R10 (Phase 3 start: fs init wired into kernel init)

- run_id: R10
- commit: same working tree + `microkernel_init` now calls `crate::fs::init()`
- command: `bash -n nonos-ci/wallpaper_round_trip.sh && nonos-ci/wallpaper_round_trip.sh`
- exit_code: 1
- log_path: `/tmp/nonos-wallpaper-smoke.log`
- first_failure_line: `[wallpaper-smoke] FAIL: missing marker: [wallpaper] display ok`
- decision: Phase 3 preconditions now proven in runtime; launch progresses through `exec_process` ELF load, but userspace wallpaper markers are still absent

Recorded constants:

- harness timeout: `240s`
- profile: `microkernel-wallpaper-smoketest`

Current boundary refinement:

- Last observed runtime marker is bootloader-side: `[INFO] kernel_verify: Cryptographic verification complete`.
- Earliest missing markers include bootloader post-verify path (`loader/handoff`) and all kernel-side markers (`[NONOS] Kernel entry`, `INIT-TRACE`, `[WALLPAPER-RC]`).
- Working root-cause candidate: stall between crypto verification completion and successful handoff/kernel entry.

Latest refinement after R8/R9:

- Bootloader compile blocker in `src/entropy/collector.rs` is fixed.
- With temporary bootloader RC markers compiled in, runtime still emits no post-verify marker.
- Updated root-cause candidate: stall inside or immediately after crypto-verification return path, before ZK-attestation marker boundary and before handoff.

Latest refinement after R10:

- The previous pre-kernel boundary is no longer valid.
- Kernel init now emits `before fs/after fs`, wallpaper seed markers, and wallpaper launch markers.
- `exec_process` no longer returns `VFS not initialized`; serial shows ELF segment loading through `[ELF] image built`.
- New boundary: post-exec handoff/user-entry for wallpaper process (no `[wallpaper]` userspace markers emitted).

## Phase 3: Seed and Launch Preconditions

Goal: prove filesystem seed and launch call are executed.

Files to instrument minimally:
- [src/fs/ops.rs](src/fs/ops.rs)
- [src/userspace/capsule_wallpaper/seed.rs](src/userspace/capsule_wallpaper/seed.rs)
- [src/userspace/init/entry.rs](src/userspace/init/entry.rs)
- [src/userspace/capsule_wallpaper/launch.rs](src/userspace/capsule_wallpaper/launch.rs)

Required temporary markers:
1. fs init entered
2. wallpaper seed attempt + result
3. `run_init` reached wallpaper smoke branch
4. launch entered
5. exec return error text (already added)

Decision:
- If seed fails: root cause in ramfs path/ordering.
- If launch branch not entered: root cause in cfg/profile mismatch.
- If launch entered and exec fails: root cause in exec preconditions.

Checklist:

- [x] fs init marker emitted
- [x] wallpaper seed attempt marker emitted
- [x] wallpaper seed result marker emitted
- [x] run_init wallpaper branch marker emitted
- [x] launch-entered marker emitted
- [x] exec failure marker (if any) captured
- [ ] Temporary markers removed after decision

Phase 3 current status:

- Instrumentation markers are now observed in live serial output.
- Filesystem seed and launch preconditions are confirmed executing.
- `VFS not initialized` path is cleared after wiring filesystem init into kernel init.
- Active boundary moved past preconditions into post-exec/user-entry behavior.

Serial channel fidelity status:

- Harness run with `-serial stdio -monitor none -nographic`: timed out at 240s with no runtime markers.
- Harness run with `-serial mon:stdio -display none` (repo-standard serial mode): same timeout and no runtime markers.
- Decision: failure is not explained by serial flag variant alone.

Marker policy:

- Prefix all temporary markers with `[WALLPAPER-RC]`
- Keep markers single-line, fixed text, no dynamic formatting

## Phase 4: Exec Failure Drilldown

Goal: isolate the exact failing precondition in `exec_process`.

File:
- [src/process/operations_exec.rs](src/process/operations_exec.rs)

Checkpoints for temporary marker on each error return branch:
1. `process has no address space allocated`
2. `invalid executable format`
3. `executable has no entry point`
4. `failed to setup user stack`
5. `entry point not in user space`
6. `stack pointer not in user space`

Decision:
- Since `exec_process` now reaches ELF image build without returning an error string, this phase should target post-exec transfer/user-entry evidence, not only error-return branches.

Checklist:

- [ ] Error branch 1 instrumented
- [ ] Error branch 2 instrumented
- [ ] Error branch 3 instrumented
- [ ] Error branch 4 instrumented
- [ ] Error branch 5 instrumented
- [ ] Error branch 6 instrumented
- [ ] First-hit branch identified from serial
- [ ] Non-hit temporary markers removed

Validation:

1. `rg -n "WALLPAPER-RC" src/process/operations_exec.rs`
2. One rerun only after instrumentation patch

## Phase 5: Fix and Verify

Goal: patch only root-cause line(s), remove temporary markers, keep harness strict.

Verification commands:
1. `bash -n nonos-ci/wallpaper_round_trip.sh`
2. `./nonos-ci/wallpaper_round_trip.sh`
3. `./nonos-ci/run-static-checks.sh`

Required runtime marker sequence:
1. `[wallpaper] display ok`
2. `[wallpaper] surface created`
3. `[wallpaper] surface filled`
4. `[wallpaper] present ok`
5. `[wallpaper] PASS`

Checklist:

- [ ] Root-cause patch applied (minimal)
- [ ] Harness still strict (no relaxed marker rules)
- [ ] Temporary RC markers removed
- [ ] Harness parse check passes
- [ ] Smoke run exits zero
- [ ] Marker order check passes
- [ ] Static checks run completed
- [ ] Unrelated pre-existing failures separated from new regressions

Regression commands:

1. `bash -n nonos-ci/wallpaper_round_trip.sh`
2. `./nonos-ci/wallpaper_round_trip.sh`
3. `./nonos-ci/run-static-checks.sh`
4. `rg -n "WALLPAPER-RC" src nonos-ci || true`

## Definition of Done

1. Harness exits zero.
2. Required wallpaper markers appear in order.
3. No temporary debug markers remain.
4. Static checks pass except unrelated pre-existing blockers.

Closure checklist:

- [ ] Root cause named in one sentence
- [ ] Fix linked to exact file and function
- [ ] Before/after evidence attached
- [ ] No temporary diagnostics left
- [ ] Harness remains deterministic
- [ ] Plan updated with final verdict

## Rollback

If any diagnosis patch regresses boot:
1. Revert only the last diagnosis patch.
2. Keep prior evidence and continue from last known good boundary.

Rollback checklist:

- [ ] Revert only latest diagnosis commit/hunk
- [ ] Re-run Phase 0 once
- [ ] Confirm failure mode unchanged from previous baseline
- [ ] Resume from prior confirmed boundary
