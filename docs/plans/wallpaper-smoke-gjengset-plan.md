# Wallpaper Smoke Fix Plan (First Principles)

Status: in-progress
Date: 2026-05-12
Branch: feat/graphics-phase0-truth-map
Scope: unblock wallpaper smoke to deterministic PASS without relaxing checks

## 1) Problem Framing

Observed runtime boundary:
- Boot reaches userspace init and wallpaper launch path.
- Direct exec fails because VFS is not initialized in this profile.
- Embedded spawn fallback now succeeds through process creation and user entry.
- Wallpaper userspace then fails at display dimensions syscall.

Current hard symptom:
- wallpaper emits FAIL display_dimensions.

## 2) Assumptions (Explicit)

1. Wallpaper smoke must validate real graphics syscall path, not parked-success fallback.
2. framebuffer_state being None is the immediate cause of display_dimensions failure.
3. Bootloader to kernel framebuffer handoff stride must be compatible with kernel graphics contract.
4. No scope expansion into unrelated desktop loop or legacy graphics paths.

## 3) Verified Context Snapshot

Entry and launch path evidence:
- [src/userspace/init/entry.rs](src/userspace/init/entry.rs#L136)
- [src/userspace/capsule_wallpaper/launch.rs](src/userspace/capsule_wallpaper/launch.rs#L62)
- [src/userspace/capsule_wallpaper/spawn.rs](src/userspace/capsule_wallpaper/spawn.rs#L21)

Spawn root-cause and fix point:
- [src/kernel_core/process_spawn/capsule_spawn/runner/install.rs](src/kernel_core/process_spawn/capsule_spawn/runner/install.rs#L66)

Graphics syscall failure gate:
- [src/syscall/dispatch/router/graphics_backend.rs](src/syscall/dispatch/router/graphics_backend.rs#L79)

Framebuffer kernel initialization contract:
- [src/kernel_core/init/framebuffer.rs](src/kernel_core/init/framebuffer.rs#L44)

Bootloader GOP handoff implementation:
- [nonos-bootloader/src/handoff/config/gop_handle.rs](nonos-bootloader/src/handoff/config/gop_handle.rs#L28)

Smoke harness behavior and strict markers:
- [nonos-ci/wallpaper_round_trip.sh](nonos-ci/wallpaper_round_trip.sh#L73)
- [nonos-ci/wallpaper_round_trip.sh](nonos-ci/wallpaper_round_trip.sh#L135)

## 4) Success Criteria

1. Smoke exits zero in one run.
2. Marker order is strict and complete:
- display ok
- surface created
- surface filled
- present ok
- PASS
3. No temporary diagnostic markers remain.
4. No relaxation of harness assertions.

## 5) Risk-Ordered Plan

### Phase A: Prove framebuffer handoff compatibility end-to-end

Goal:
- Prove that kernel receives usable framebuffer state for graphics syscalls.

Actions:
1. Keep bootloader stride as 4-byte aligned in GOP handoff.
2. Add one temporary kernel marker at framebuffer init success and one at early return reason.
3. Rerun smoke once and capture first decisive marker.

Verification:
1. Smoke run reaches wallpaper launch.
2. Serial contains framebuffer init success marker before wallpaper user entry.
3. display_dimensions returns success.

Exit gate:
- If framebuffer init still absent, continue to Phase B.
- If present and display_dimensions still fails, continue to Phase C.

### Phase B: Isolate framebuffer init rejection branch

Goal:
- Identify exact rejection in framebuffer init path.

Actions:
1. Instrument only branch points in init_framebuffer:
- no framebuffer in handoff
- invalid geometry
- stride too small
- mmio map fail
2. Rerun smoke once.
3. Remove non-winning instrumentation after identifying first-hit branch.

Verification:
1. One branch-specific failure marker appears.
2. Marker maps directly to one check in framebuffer init.

Exit gate:
- Single branch identified with concrete reason.

### Phase C: Apply minimal fix for the identified branch

Goal:
- Change only the failing precondition path.

Actions:
1. Patch one function only unless impossible.
2. Re-run smoke.
3. Confirm ordered wallpaper markers and zero exit.

Verification:
1. display_dimensions passes.
2. Full marker chain appears in order.
3. Harness reports PASS.

Exit gate:
- PASS achieved.

### Phase D: Cleanup and hardening checks

Goal:
- Leave no temporary diagnostics and keep strict policy.

Actions:
1. Remove all temporary RC markers added during phases A-B.
2. Re-run smoke once.
3. Run static checks if needed for touched files.

Verification:
1. No temporary marker strings remain in source.
2. Smoke still PASS.

## 6) Command Runbook

1. bash -n nonos-ci/wallpaper_round_trip.sh
2. nonos-ci/wallpaper_round_trip.sh
3. rg -n "WALLPAPER-RC|FB-RC|framebuffer" src nonos-bootloader

If static checks required by touched scope:

4. nonos-ci/run-static-checks.sh

## 7) Rollback Strategy

1. Revert only the latest failing phase patch.
2. Keep evidence from the previous known-good boundary.
3. Re-run one smoke to confirm boundary did not move backward.

## 8) Non-Goals

1. No broad refactors in scheduler, desktop loop, or unrelated subsystem cleanup.
2. No weakening of smoke pass criteria.
3. No adding parked-success behavior to wallpaper smoke binary.
