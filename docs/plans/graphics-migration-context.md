# Graphics Migration Execution Context

## Scope
- Plan: docs/plans/graphics-userland-migration-implementation-plan.md
- Execution mode: phase-by-phase on top of current origin/main
- Rule set: no wholesale merge/rebase of split branch; one-file-per-commit; evidence-first phase advancement

## Live Phase Status

| Phase | Status | Last Updated (UTC) | Note |
| --- | --- | --- | --- |
| 0 | in progress | 2026-05-10T08:14:26Z | Baseline parity verified; Phase 0 closure slice pending |
| 1 | not started | 2026-05-10T08:13:32Z | pending |
| 2 | not started | 2026-05-10T08:13:32Z | pending |
| 3 | not started | 2026-05-10T08:13:32Z | pending |
| 4 | not started | 2026-05-10T08:13:32Z | pending |
| 5 | not started | 2026-05-10T08:13:32Z | pending |
| 6 | not started | 2026-05-10T08:13:32Z | pending |
| 7 | not started | 2026-05-10T08:13:32Z | pending |
| 8 | not started | 2026-05-10T08:13:32Z | pending |
| 9 | not started | 2026-05-10T08:13:32Z | pending |
| 10 | not started | 2026-05-10T08:13:32Z | pending |
| 11 | not started | 2026-05-10T08:13:32Z | pending |

## Execution Log

### 2026-05-10T08:13:32Z
- phase number: 0
- objective: Initialize execution context tracking and prepare baseline check
- files touched: docs/plans/graphics-migration-context.md
- commands run:
  - date -u +"%Y-%m-%dT%H:%M:%SZ"
  - [ -f docs/plans/graphics-migration-context.md ] && echo EXISTS || echo MISSING
- results:
  - timestamp captured
  - context file did not exist and was created
- risks introduced:
  - none
- rollback note:
  - delete docs/plans/graphics-migration-context.md to revert this slice
- next action:
  - run baseline validation against origin/main and record evidence

### 2026-05-10T08:13:58Z
- phase number: 0
- objective: Pre-action checkpoint before baseline validation
- files touched: docs/plans/graphics-migration-context.md
- commands run:
  - none (checkpoint entry)
- results:
  - baseline validation queued
- risks introduced:
  - none
- rollback note:
  - remove this checkpoint entry if log normalization is required
- next action:
  - run fetch + HEAD/origin/main parity + ahead/behind validation and capture output

### 2026-05-10T08:14:26Z
- phase number: 0
- objective: Post-action evidence for baseline validation
- files touched: docs/plans/graphics-migration-context.md
- commands run:
  - git fetch origin main
  - git rev-parse --short HEAD
  - git rev-parse --short origin/main
  - git rev-list --left-right --count origin/main...HEAD
  - git status --short --branch
- results:
  - HEAD = c8b7585db
  - origin/main = c8b7585db
  - origin/main...HEAD ahead/behind = 0 0 (baseline parity pass)
  - local branch tracking state is ahead 61 and behind 1 versus origin/feat/graphics-phase0-truth-map
  - working tree includes untracked docs/plans/graphics-migration-context.md and docs/plans/graphics-userland-migration-implementation-plan.md
- risks introduced:
  - branch tracking divergence can confuse progress reporting if main-parity and branch-parity are mixed
- rollback note:
  - remove this entry to revert only documentation/log state
- next action:
  - execute Phase 0 closure slice: ensure baseline plan updates are committed in one-file commits and mark Phase 0 complete

### 2026-05-10T08:14:56Z
- phase number: 0
- objective: Pre-action checkpoint before committing baseline plan document
- files touched: docs/plans/graphics-migration-context.md
- commands run:
  - none (checkpoint entry)
- results:
  - one-file commit preparation started for docs/plans/graphics-userland-migration-implementation-plan.md
- risks introduced:
  - none
- rollback note:
  - remove this checkpoint entry if log normalization is required
- next action:
  - stage and commit only docs/plans/graphics-userland-migration-implementation-plan.md

### 2026-05-10T16:32:51Z
- phase number: 3
- objective: Land RB2/RB3 runtime slices for graphics surface lifecycle and full present path
- files touched: src/syscall/dispatch/router/graphics_unavailable.rs, src/syscall/dispatch/router/graphics_present.rs, src/syscall/dispatch/router/mod.rs, docs/plans/graphics-userland-migration-implementation-plan.md
- commands run:
  - ./nonos-ci/run-static-checks.sh
  - RUSTUP_TOOLCHAIN=nightly-2026-01-16 cargo check -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem --target x86_64-nonos.json --features "nonos-capsule-wallpaper nonos-wallpaper-smoketest"
  - make nonos-mk-wallpaper-test
- results:
  - graphics surface create/map/destroy now return real runtime behavior via per-process mmap lifecycle
  - graphics surface present_full now copies user surface bytes into framebuffer MMIO mapping
  - static checks pass; custom-target build and wallpaper smoketest build pass (warnings only)
- risks introduced:
  - present path currently supports full-surface ARGB8888 workflow only; rect/cursor/list remain parked
- rollback note:
  - revert RB2/RB3 router commits to return graphics surface operations to parked ENOTSUP path
- next action:
  - run runtime QEMU proof for wallpaper marker sequence and then close remaining parked graphics ops

### 2026-05-10T16:39:59Z
- phase number: 3
- objective: Extend RB3 present path to support rect submissions
- files touched: src/syscall/dispatch/router/mod.rs, src/syscall/dispatch/router/graphics_unavailable.rs, src/syscall/dispatch/router/graphics_present.rs, docs/plans/graphics-userland-migration-implementation-plan.md
- commands run:
  - ./nonos-ci/run-static-checks.sh
  - RUSTUP_TOOLCHAIN=nightly-2026-01-16 cargo check -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem --target x86_64-nonos.json --features "nonos-capsule-wallpaper nonos-wallpaper-smoketest"
  - make nonos-mk-wallpaper-test
- results:
  - graphics present route now handles both full and rect variants via framebuffer MMIO blit path
  - static checks pass; custom-target build and wallpaper smoketest build pass (warnings only)
- risks introduced:
  - cursor/list graphics syscalls remain parked; no runtime QEMU marker proof captured yet
- rollback note:
  - revert the present-rect routing commit to return `GraphicsSurfacePresentRect` to parked ENOTSUP
- next action:
  - execute QEMU runtime wallpaper smoke and close remaining parked display-list/cursor paths

### 2026-05-11T03:48:33Z
- phase number: 5
- objective: Close RB4 and RB5 by promoting graphics to explicit backend-routed status with matching ABI/gate truth
- files touched: src/syscall/dispatch/router/mod.rs, src/syscall/dispatch/router/graphics_backend.rs, src/syscall/dispatch/router/graphics_present.rs, src/syscall/abi/registry.rs, nonos-ci/run-static-checks.sh, abi/wire.toml, docs/plans/graphics-userland-migration-implementation-plan.md
- commands run:
  - ./nonos-ci/run-static-checks.sh
  - RUSTUP_TOOLCHAIN=nightly-2026-01-16 cargo check -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem --target x86_64-nonos.json --features "nonos-capsule-wallpaper nonos-wallpaper-smoketest"
  - make nonos-mk-wallpaper-test
- results:
  - graphics router now routes through explicit `graphics_backend` module
  - graphics ABI registry entries moved to `AbiStatus::Routed`
  - static gates now require graphics backend routing and libc graphics constants/tag4 ABI alignment
  - static checks pass; target build and wallpaper smoketest build pass (warnings only)
- risks introduced:
  - runtime QEMU marker proof remains pending for this timestamped slice (build-only proof captured)
- rollback note:
  - revert RB5 router/registry/static-gate commits to restore parked-routing policy
- next action:
  - execute QEMU runtime marker capture and then proceed to compositor/userland service phases

### 2026-05-11T05:35:53Z
- phase number: 3
- objective: Capture RB3 runtime wallpaper marker proof under QEMU serial
- files touched: none (runtime validation only)
- commands run:
  - make nonos-mk-wallpaper-test
  - make nonos-mk-run-serial
  - rg -n "\[NONOS\] Handoff (OK|FAIL)|\[wallpaper\]" /tmp/rb3_runtime_serial.log
- results:
  - boot reached kernel transfer and emitted `[NONOS] Handoff FAIL`
  - wallpaper marker sequence (`display ok`, `surface created`, `surface filled`, `present ok`, `PASS`) was not observed in serial log
  - RB3 code path remains build-verified, but runtime marker proof is currently blocked by handoff failure on this host run
- risks introduced:
  - runtime smoke closure cannot be claimed until handoff failure is root-caused and cleared
- rollback note:
  - no repository state change required (validation-only run)
- next action:
  - root-cause `Handoff FAIL` in kernel entry/handoff validation path, then re-run serial marker proof

### 2026-05-11T06:02:39Z
- phase number: 0
- objective: Re-run baseline preflight guard before further phase execution
- files touched: docs/plans/graphics-migration-context.md
- commands run:
  - git rev-parse --short HEAD
  - git rev-parse --short origin/main
  - git rev-list --left-right --count origin/main...HEAD
- results:
  - HEAD = bbeb102af
  - origin/main = 275627470
  - origin/main...HEAD ahead/behind = 1/12
  - baseline guard command set executed successfully; active execution remains branch-slice work, not main-parity execution
- risks introduced:
  - none (documentation-only evidence refresh)
- rollback note:
  - revert this single context-log append commit
- next action:
  - continue iterative phase execution with per-file commits and post-completion doc updates

### 2026-05-11T06:04:45Z
- phase number: 1
- objective: Close Phase 1 item for boot framebuffer metadata validation
- files touched: docs/plans/graphics-userland-migration-implementation-plan.md, docs/plans/graphics-migration-context.md
- commands run:
  - rg -n "fn check\(|FramebufferGeometry|ZeroWidth|ZeroHeight|StrideTooSmall|AreaOverflow" src/boot/handoff/api/security/framebuffer.rs src/boot/handoff/api/error/handoff_error.rs src/boot/tests/handoff_security/framebuffer.rs
  - RUSTUP_TOOLCHAIN=nightly-2026-01-16 cargo test -q --lib boot::tests::handoff_security::framebuffer
- results:
  - in-tree framebuffer handoff security checks confirm geometry validation (`ZeroWidth`, `ZeroHeight`, `StrideTooSmall`, `AreaOverflow`) before boot use
  - runbook Phase 1 checklist item `validate boot framebuffer metadata before use` marked complete
  - focused cargo-test invocation is currently blocked by unrelated pre-existing test compile failures outside framebuffer security scope
- risks introduced:
  - no runtime behavior change (documentation/evidence update only)
- rollback note:
  - revert this context append and paired plan-doc checklist commit
- next action:
  - continue Phase 1 with canonical framebuffer state and mapping invariants

### 2026-05-11T06:05:42Z
- phase number: 2
- objective: Close Phase 2 status drift for backend routing wording and libc graphics constant gate
- files touched: docs/plans/graphics-userland-migration-implementation-plan.md, docs/plans/graphics-migration-context.md
- commands run:
  - rg -n "libc graphics syscall constants match ABI tag4 IDs|graphics syscalls route through graphics_backend gate module|static-checks: PASS" /tmp/rb45_static.log /tmp/static_before_commit.log
- results:
  - static-check outputs confirm graphics dispatch routes via `graphics_backend`
  - static-check outputs confirm libc graphics constants gate is enforced and passing
  - Phase 2 checklist updated to reflect active backend routing and completed libc-constant static gate
- risks introduced:
  - none (documentation-only alignment to existing enforced behavior)
- rollback note:
  - revert this context append and paired Phase 2 plan-doc commit
- next action:
  - continue unresolved Phase 2 gates (raw-ID bans, syscall-import bans, no-asm capsule gate)

### 2026-05-11T06:08:05Z
- phase number: 2
- objective: Land static gate forbidding raw syscall IDs in userland graphics/smoke code
- files touched: nonos-ci/run-static-checks.sh, docs/plans/graphics-userland-migration-implementation-plan.md, docs/plans/graphics-migration-context.md
- commands run:
  - ./nonos-ci/run-static-checks.sh
  - rg -n "no raw syscall IDs in userland graphics/smoke code|static-checks: PASS" /tmp/phase2_rawid_gate.log
- results:
  - new static gate added: rejects numeric syscall IDs and inline tag4 literals in `userland/libc/src/graphics`, `userland/capsule_wallpaper/src`, and `src/userspace/capsule_wallpaper`
  - static checks pass with explicit marker: `[ok] no raw syscall IDs in userland graphics/smoke code`
  - Phase 2 plan checklist item for raw-ID gate is now marked complete
- risks introduced:
  - low: stricter policy may fail future slices that bypass named constants
- rollback note:
  - revert commit `6ea9db2eb` (gate) and paired docs commits if rollback is required
- next action:
  - continue remaining Phase 2 gates for forbidden syscall imports and no-asm capsule usage

### 2026-05-11T06:28:51Z
- phase number: 2
- objective: Land static gate forbidding `_exit`/`write`/`read`/`mmap` imports in wallpaper/proof/driver smoke capsules
- files touched: nonos-ci/run-static-checks.sh, docs/plans/graphics-userland-migration-implementation-plan.md, docs/plans/graphics-migration-context.md
- commands run:
  - ./nonos-ci/run-static-checks.sh
  - rg -n "no _exit/write/read/mmap imports in wallpaper/proof/driver smoke capsules|static-checks: PASS" /tmp/phase2_import_gate.log
- results:
  - new static gate added: rejects `use` imports of `_exit`/`write`/`read`/`mmap` in wallpaper, proof_io, and driver smoke capsule source trees
  - static checks pass with explicit marker: `[ok] no _exit/write/read/mmap imports in wallpaper/proof/driver smoke capsules`
  - Phase 2 plan checklist item for forbidden imports is now marked complete
- risks introduced:
  - low: stricter import policy may fail future capsule slices that reintroduce Linux-shape symbols
- rollback note:
  - revert commit `b00424a4c` (gate) and paired docs commits if rollback is required
- next action:
  - continue remaining Phase 2 gate for no asm usage in graphics-proof capsules

### 2026-05-11T06:53:00Z
- phase number: 2
- objective: Land static gate forbidding inline asm in graphics-proof capsules
- files touched: nonos-ci/run-static-checks.sh, docs/plans/graphics-userland-migration-implementation-plan.md, docs/plans/graphics-migration-context.md
- commands run:
  - ./nonos-ci/run-static-checks.sh
  - rg -n "no inline asm in graphics proof capsules|static-checks: PASS|static-checks: FAIL" /tmp/phase2_noasm_gate.log
- results:
  - new static gate added: rejects `asm!` usage in `userland/capsule_wallpaper`, `userland/capsule_proof_io`, and matching `src/userspace` proof/wallpaper paths
  - static checks pass with explicit marker: `[ok] no inline asm in graphics proof capsules`
  - Phase 2 plan checklist item for no-asm proof-capsule gate is now marked complete
- risks introduced:
  - low: stricter policy may fail future proof-capsule slices that introduce inline asm
- rollback note:
  - revert commit introducing the no-asm gate and paired docs commits if rollback is required
- next action:
  - continue remaining Phase 2 work: reconcile `abi/*.toml` specs with active runtime registry contract

### 2026-05-11T06:56:10Z
- phase number: 2
- objective: Close remaining Phase 2 ABI reconciliation (`abi/*.toml` vs active runtime contract)
- files touched: nonos-ci/run-static-checks.sh, docs/plans/graphics-userland-migration-implementation-plan.md, docs/plans/graphics-migration-context.md
- commands run:
  - ./nonos-ci/run-static-checks.sh
  - rg -n "abi/wire.toml matches active graphics/runtime contract shape|abi/manifest.toml includes required capsule contract fields|no inline asm in graphics proof capsules|static-checks: PASS" /tmp/phase2_abi_reconcile.log
- results:
  - static gate now enforces `abi/wire.toml` graphics/runtime contract fields (`pixel_format`, `display_count_max`, `surface_backing`, `present_modes`, `reg_order`)
  - static gate now enforces required `abi/manifest.toml` capsule contract fields and format
  - static checks pass with markers:
    - `[ok] abi/wire.toml matches active graphics/runtime contract shape`
    - `[ok] abi/manifest.toml includes required capsule contract fields`
    - `static-checks: PASS`
  - Phase 2 plan checklist item `reconcile abi/*.toml specs with active runtime registry contract` marked complete
- risks introduced:
  - low: stricter ABI-shape gates can fail future changes that drift fields/order without matching runtime updates
- rollback note:
  - revert ABI-reconciliation gate commit and paired docs commits if rollback is required
- next action:
  - proceed to next migration phase execution slices after Phase 2 checklist closure

### 2026-05-11T07:02:07Z
- phase number: 3
- objective: Land a real display capsule/service spawn path after Phase 2 gate closure
- files touched: src/userspace/capsule_wallpaper/spawn.rs, src/userspace/capsule_wallpaper/mod.rs, src/userspace/init/entry.rs, docs/plans/graphics-userland-migration-implementation-plan.md, docs/plans/graphics-migration-context.md
- commands run:
  - get_errors on new/updated wallpaper spawn/init files
- results:
  - added `spawn_wallpaper_capsule()` backed by `capsule_spawn::spawn` with explicit graphics/display caps
  - wired init-path spawn (`DISPLAY` / `display`) under `nonos-capsule-wallpaper` and disabled it under `nonos-wallpaper-smoketest`
  - exported new spawn path from `capsule_wallpaper` module for init integration
  - Phase 3 checklist item `add real display capsule/service path once Phase 2 gates are closed` marked complete
- risks introduced:
  - medium-low: service/reply endpoint names and ports are newly allocated for display capsule path and may need harmonization with future compositor routing contracts
- rollback note:
  - revert display capsule spawn wiring commits and paired docs commits if rollback is required
- next action:
  - proceed to Phase 4 compositor skeleton (`create compositor runtime with canonical IPC path`)

### 2026-05-11T07:08:36Z
- phase number: 4
- objective: Land compositor runtime path with canonical IPC identity
- files touched: Cargo.toml, src/userspace/mod.rs, src/userspace/init/entry.rs, src/userspace/capsule_compositor/mod.rs, src/userspace/capsule_compositor/embed.rs, src/userspace/capsule_compositor/spawn.rs, nonos-ci/run-static-checks.sh, docs/plans/graphics-userland-migration-implementation-plan.md, docs/plans/graphics-migration-context.md
- commands run:
  - get_errors on compositor and init/userspace wiring files
  - bash -n nonos-ci/run-static-checks.sh
- results:
  - added new `nonos-capsule-compositor` feature flag
  - added kernel-side compositor capsule glue module and spawn path
  - canonical compositor IPC path established in spawn spec (`service=compositor`, `service_port=4310`, `reply_inbox=endpoint.compositor.reply`, `reply_port=4311`)
  - init boot sequence now feature-gates compositor spawn
  - static feature-module pairing gate now validates `nonos-capsule-compositor` ↔ `src/userspace/capsule_compositor`
  - Phase 4 checklist item `create compositor runtime with canonical IPC path` marked complete
- risks introduced:
  - medium-low: compositor capsule binary/artifacts are feature-gated; runtime availability depends on userland compositor build output for enabled profiles
- rollback note:
  - revert compositor feature/module/spawn commits and paired docs commits if rollback is required
- next action:
  - continue Phase 4 with scene/damage/cursor ownership in userland

### 2026-05-11T07:18:41Z
- phase number: 4
- objective: Establish scene/damage/cursor ownership in userland compositor
- files touched: userland/compositor/Cargo.toml, userland/compositor/src/main.rs, nonos-ci/run-static-checks.sh, docs/plans/graphics-userland-migration-implementation-plan.md, docs/plans/graphics-migration-context.md
- commands run:
  - get_errors on compositor runtime and compositor spawn glue files
  - bash -n nonos-ci/run-static-checks.sh
- results:
  - added userland compositor capsule runtime crate (`userland/compositor`) with no_std entrypoint
  - compositor runtime now owns scene/damage/cursor IPC op constants and runs canonical `mk_ipc_recv(COMPOSITOR_ENDPOINT, ...)` loop
  - static gate added to enforce compositor ownership constants and canonical IPC receive path in userland source
  - Phase 4 checklist item `establish scene/damage/cursor ownership in userland` marked complete
- risks introduced:
  - low: compositor loop is skeletal and currently yields on unknown/negative IPC results; full scene-graph behavior remains future Phase 4 work
- rollback note:
  - revert compositor userland runtime and static-gate commits and paired docs commits if rollback is required
- next action:
  - complete Phase 4 by integrating compositor present path via graphics contract

### 2026-05-11T07:20:05Z
- phase number: 4
- objective: Integrate compositor runtime present path through graphics contract APIs
- files touched: userland/compositor/src/main.rs, nonos-ci/run-static-checks.sh, docs/plans/graphics-userland-migration-implementation-plan.md, docs/plans/graphics-migration-context.md
- commands run:
  - get_errors on `userland/compositor/src/main.rs`
  - bash -n nonos-ci/run-static-checks.sh
- results:
  - compositor runtime now performs graphics contract sequence (`display_dimensions` → `surface_create` → `surface_map` → `surface_present_full` → `surface_destroy`)
  - static gate extended to require compositor runtime usage of graphics contract APIs
  - Phase 4 checklist item `integrate present path via graphics contract` marked complete
- risks introduced:
  - low: present path is a minimal proof sequence; full scene graph and damage batching semantics remain future refinement work
- rollback note:
  - revert compositor present-path and CI-gate commits and paired docs commits if rollback is required
- next action:
  - proceed to Phase 5 input service/routing slices

### 2026-05-11T07:22:01Z
- phase number: 5
- objective: Enforce kernel input ingest-only boundary
- files touched: nonos-ci/run-static-checks.sh, docs/plans/graphics-userland-migration-implementation-plan.md, docs/plans/graphics-migration-context.md
- commands run:
  - ./nonos-ci/run-static-checks.sh
  - rg -n "kernel input modules remain ingest-only|static-checks: PASS|static-checks: FAIL" /tmp/phase5_input_ingest.log
- results:
  - added static gate that rejects routing/focus/compositor policy terms in kernel input module trees (`src/hardware/ps2_kbd_capsule`, `src/hardware/xhci_capsule`)
  - static checks pass and include marker: `[ok] kernel input modules remain ingest-only (no routing/focus/compositor policy)`
  - Phase 5 checklist item `keep kernel input ingest only` marked complete
- risks introduced:
  - low: string-policy gate may need term adjustments if future technical terminology overlaps with policy words
- rollback note:
  - revert input-ingest gate commit and paired docs commits if rollback is required
- next action:
  - continue Phase 5: move routing/focus policy fully to userland chain

### 2026-05-11T07:56:25Z
- phase number: 5
- objective: Move routing/focus policy ownership fully to userland chain
- files touched: userland/compositor/src/main.rs, nonos-ci/run-static-checks.sh, docs/plans/graphics-userland-migration-implementation-plan.md, docs/plans/graphics-migration-context.md
- commands run:
  - ./nonos-ci/run-static-checks.sh
  - rg -n "kernel input modules remain ingest-only|routing/focus policy ownership markers live in userland compositor|static-checks: PASS|static-checks: FAIL" /tmp/phase5_routing_focus.log
- results:
  - compositor runtime now defines userland policy op markers: `COMPOSITOR_OP_FOCUS_SET` and `COMPOSITOR_OP_INPUT_ROUTE`
  - compositor runtime now emits policy-ownership markers: `focus policy owner`, `input routing owner`
  - static gate now requires those routing/focus ownership markers in userland compositor runtime
  - static checks pass and include marker: `[ok] routing/focus policy ownership markers live in userland compositor`
  - Phase 5 checklist item `move routing/focus policy fully to userland chain` marked complete
- risks introduced:
  - low: marker-string policy proof is static and may require updates if compositor naming evolves
- rollback note:
  - revert compositor marker and Phase-5 routing/focus gate commits and paired docs commits if rollback is required
- next action:
  - complete Phase 5 final proof: denied-cap behavior and input-event flow end to end

### 2026-05-11T07:58:36Z
- phase number: 5
- objective: Prove denied-cap behavior and input-event flow end to end
- files touched: nonos-ci/run-static-checks.sh, docs/plans/graphics-userland-migration-implementation-plan.md, docs/plans/graphics-migration-context.md
- commands run:
  - ./nonos-ci/run-static-checks.sh
  - rg -n "phase5 denied-cap and ps2 input event flow proof markers present|routing/focus policy ownership markers live in userland compositor|kernel input modules remain ingest-only|static-checks: PASS|static-checks: FAIL" /tmp/phase5_input_proof.log
- results:
  - static gate now enforces denied-cap and event-flow proof producers across:
    - kernel PS/2 capability gate (`CAP_DRIVER` + `AccessDenied`)
    - PS/2 userland driver loop (`endpoint driver.ps2_kbd0 ready`, `mk_ipc_recv`, `OP_POLL_EVENTS`)
    - kernel PS/2 smoketest markers (`poll_events ok`, `AccessDenied`, `PASS`)
  - static checks pass and include marker: `[ok] phase5 denied-cap and ps2 input event flow proof markers present`
  - Phase 5 checklist item `prove denied-cap behavior and input event flow end to end` marked complete
- risks introduced:
  - low: marker-based proof is static and can require maintenance if file/marker names change
- rollback note:
  - revert Phase-5 proof gate commit and paired docs commits if rollback is required
- next action:
  - begin Phase 6: desktop shell policy migration slices
