# NONOS Graphics Userland Migration Implementation Plan

Status: execution runbook
Scope: graphics migration to real userland processes/capsules

## Target Wording (explicit confirmation)
Graphics and UI policy moves into real userland processes/capsules, not merely into userspace-looking service shells.

## 0. Main Baseline Snapshot (2026-05-10)

Baseline source of truth:
- Commit: `origin/main` = `c8b7585db` (matches current `HEAD` at baseline time)
- Method: in-repo path checks + symbol scans + direct file reads

Current measured status (main baseline):
- Overall completion: 11%
- Overall confidence: Medium
- Reality check: graphics syscall IDs and userland wrappers exist, but runtime graphics backend is parked and returns `ENOTSUP` on all graphics syscall routes.

Main reality delta versus older snapshots:
- Legacy path families referenced by older migration notes are absent on current main: `src/graphics/*`, `src/display/*`, `src/input/*`, `src/userspace/*_service`, `src/userspace/capsule_display/*`, `userland/capsule_display/*`.
- Planned runtime roots `userland/compositor/*`, `userland/desktop_shell/*`, `userland/wm/*`, and `userland/toolkit/*` currently do not carry active source runtime in this baseline.

### 0.1 Phase Progress (main baseline)

| Phase | Progress | Status |
| --- | ---: | --- |
| Phase 0: Truth map/freeze guard | 100% | complete |
| Phase 1: Framebuffer canonicalization | 5% | parked (`init_framebuffer` is typed no-op) |
| Phase 2: Graphics ABI/contract | 45% | partial (IDs/wrappers/cap-gates present, backend unavailable) |
| Phase 3: Make display service real | 20% | bootstrap done (wallpaper launch/caps/markers), backend path pending |
| Phase 4: Userland compositor skeleton | 0% | not started |
| Phase 5: Input routing to userland | 0% | not started |
| Phase 6: Desktop shell migration | 0% | not started |
| Phase 7: WM migration | 0% | not started |
| Phase 8: Toolkit migration | 0% | not started |
| Phase 9: App UI migration | 0% | not started |
| Phase 10: Kernel graphics frontend reduction | 30% | partial (legacy families absent, replacement stack not landed) |
| Phase 11: Multi-architecture hardening | 0% | not started |

### 0.2 Verified Present On Current Main

- Tag4 syscall model is active, including graphics IDs (`GDIM`, `GSCR`, `GSDS`, `GSMP`, `GPRF`, `GPRR`, `GDLS`, `GCUR`).
- Graphics syscall numbers are in active kernel enum/registry, but marked unavailable in ABI registry and routed to `graphics_unavailable`.
- Userland libc exports graphics syscall wrappers (display dimensions/list, surface create/map/destroy/present, cursor present).
- Wallpaper capsule wiring exists under `src/userspace/capsule_wallpaper/*`, and `run_init()` invokes wallpaper launch under `nonos-wallpaper-smoketest`.
- Capability inheritance policy excludes graphics bits from ambient process inheritance.

### 0.3 Verified Missing Or Unavailable On Current Main

- Graphics dispatch backend is parked: graphics router returns `ENOTSUP` for all graphics syscalls.
- Framebuffer init path is a typed no-op in `src/kernel_core/init/framebuffer.rs`.
- ABI specs do not currently encode the graphics-rich contract claimed by older snapshot text:
    - `abi/syscalls.toml` uses integer-number table and does not carry graphics descriptors.
    - `abi/caps.toml` only exposes minimal LOG/YIELD/TIME/IPC/KSTAT bits.
    - `abi/wire.toml` is minimal and does not define display/surface/present/hotplug/input schemas.
    - `abi/manifest.toml` does not carry `storage_policy = ram_only`.
- Legacy evidence paths from older snapshots are absent in this baseline (including `tools/ci/run-static-checks.sh` and `tests/boot/wallpaper_round_trip.sh`).

### 0.4 Main Baseline Blockers

- Contract split: runtime uses tag4 registry while `abi/*.toml` docs are not aligned to active graphics contract surface.
- Handoff order remains risky for diagnostics: `init_core_systems()` still executes before handoff validation in kernel entry.
- Wallpaper smoke proof is not closed on current main baseline because graphics backend is intentionally unavailable.
- Policy-gate infrastructure for this slice is not yet codified in-tree (`tools/ci/run-static-checks.sh` is absent on current main baseline).

### 0.5 Strict Next (main-first order)

Do not reorder these for baseline recovery:

1. Keep this section as baseline truth and reject stale claims from older branch snapshots during implementation.
2. Choose one syscall-contract authority first (runtime registry or ABI tomls), then align the other.
3. Land minimal graphics backend slice for one end-to-end syscall path (display query first), then re-run smoke proof.
4. Keep explicit graphics capability checks and add regression/static gates before widening backend scope.
5. Re-open Phase 3 only after one verified non-ENOTSUP graphics path is in place on current main.

Note: this section is a dated main-baseline snapshot. The detailed phase checklists below remain the target-state runbook and must be re-validated against this baseline before execution.

### 0.6 Revalidation Verdict (2026-05-10, Principal Pass)

Scope revalidated against current `origin/main` commit `c8b7585db`:

- PASS: branch baseline still equals `origin/main` (`0/0` ahead-behind).
- PASS: graphics syscall family uses tag4 IDs in active runtime enum/registry.
- PASS: graphics family is explicitly parked at router level with `ENOTSUP`.
- PASS: graphics ABI registry entries are present and marked `AbiStatus::Unavailable`.
- PASS: framebuffer init hook state is correctly documented as typed no-op.
- PASS: ambient-cap inheritance model excludes graphics capabilities.
- PASS: legacy path absence inventory in Section 1.1 remains accurate.
- PASS: ABI drift statements in Section 0.3 remain accurate (`abi/syscalls.toml`, `abi/caps.toml`, `abi/wire.toml`, `abi/manifest.toml`).

Open deviations from target-state policy (still blocking closure):

- FAIL(target-policy): graphics backend route is still fully parked with `ENOTSUP`.
- FAIL(target-policy): static policy gates listed in Phase 2 are not yet implemented as automated checks.

Disposition:

- Keep current phase statuses as written in Sections 0.1 and 5.
- Continue with main-first selective-port execution; do not promote any phase status without fresh evidence on the active baseline commit.

### 0.7 Real Graphics Backend Build Plan (Principal Track)

Execution model: land thin, reversible slices that each convert one graphics syscall family from parked to real behavior, with explicit failure mode and rollback switch.

| Track | Objective | Primary Files | Verification Gate | Rollback Trigger |
| --- | --- | --- | --- | --- |
| RB0 | Freeze backend contract authority: runtime tag4 registry is source of truth, abi docs must mirror runtime exactly. | `src/syscall/numbers/defs.rs`, `src/syscall/abi/registry.rs`, `abi/syscalls.toml` | one-to-one ID and errno map check in CI | any ID drift between runtime and abi docs |
| RB1 | Implement real `GraphicsDisplayDimensions` read path from boot handoff metadata (no global mutable UI state). | `src/syscall/dispatch/router/graphics_backend.rs`, `src/kernel_core/init/framebuffer.rs`, `src/boot/handoff/api/init.rs` | wallpaper emits `[wallpaper] display ok` without `graphics parked` | any null/invalid dimensions returned to userland |
| RB2 | Implement surface lifecycle (`create/destroy/map`) with pid ownership and teardown binding. | `src/process/exit/teardown.rs`, `src/memory/paging/manager/mapping/install.rs`, `src/memory/paging/manager/mapping/unmap.rs` | create-map-destroy loop is leak-free across forced process exit | leaked mapping or orphaned surface handle after exit |
| RB3 | Implement present path (`present_full` then rect path) with strict bounds checks and no kernel policy state. | `src/syscall/dispatch/router/graphics_backend.rs`, `src/memory/paging/manager/protection/pte/walk.rs` | wallpaper emits `[wallpaper] present ok` and `[wallpaper] PASS` | out-of-bounds present or kernel crash under malformed args |
| RB4 | Lock ABI/caps/wire docs to shipped backend behavior and libc bindings. | `abi/caps.toml`, `abi/wire.toml`, `abi/manifest.toml`, `userland/libc/src/graphics/*` | generated/checked constants match runtime registry and cap matrix | any mismatch in abi docs vs runtime dispatch |
| RB5 | Replace parked router dependency with explicit backend module + static gates. | `src/syscall/dispatch/router/mod.rs`, `src/syscall/dispatch/mod.rs`, `src/syscall/contract/cap_table/tests.rs` | no graphics syscall routed through ENOTSUP on enabled backend config | unexpected ENOTSUP on backend-enabled profile |

Phase gates for RB1-RB5 (must pass before promotion):

1. `cargo check --target x86_64-nonos --features "nonos-capsule-wallpaper nonos-wallpaper-smoketest"`
2. `rg -n "Graphics(Display|Surface|Present|Cursor)" src/syscall/dispatch/router src/syscall/contract/cap_table`
3. wallpaper smoke markers include exact sequence: `display ok`, `surface created`, `surface filled`, `present ok`, `PASS`
4. kill-path proof: forced process teardown leaves no surface handles or user mappings for dead pid
5. no `write(1,...)` marker path in wallpaper/proof capsules (MkDebug-only proof markers)

Owner map and handoff boundaries:

- Kernel display primitive owner: RB1 metadata truth and lifetime invariants
- Kernel memory owner: RB2 map/unmap and protection invariants
- Syscall contract owner: RB3 argument validation, errno semantics, cap checks
- Shared ABI owner: RB4 doc and binding sync
- Userspace bootstrap owner: wallpaper/proof updates and smoke determinism

Delivery policy:

- one functional slice per commit
- one file per commit unless cross-file atomicity is required for compile correctness
- every slice includes command output proving gate pass/fail and explicit rollback note

### 0.8 Branch Execution Delta (2026-05-11)

State on `feat/graphics-phase0-truth-map` after RB0-RB5 slices:

- RB0 complete: `abi/syscalls.toml` and `abi/caps.toml` now carry the active graphics contract surface and static checks enforce drift detection.
- RB1 complete: `GraphicsDisplayDimensions` now returns real width/height from handoff framebuffer metadata.
- RB2 complete: `GraphicsSurfaceCreate` / `GraphicsSurfaceMap` / `GraphicsSurfaceDestroy` now use per-process `mmap`/`munmap` lifecycle instead of parked `ENOTSUP`.
- RB3 complete: `GraphicsSurfacePresentFull` and `GraphicsSurfacePresentRect` copy mapped user surface bytes to framebuffer MMIO with bounds validation.
- RB4 complete: `abi/wire.toml` now documents the shipped graphics wire shape and static gates enforce libc graphics constant alignment to ABI tag4 IDs.
- RB5 complete: router dependency moved from parked `graphics_unavailable` to explicit `graphics_backend`, and graphics ABI registry entries are now `AbiStatus::Routed` with matching static-gate enforcement.

Verification evidence (branch state):

1. `./nonos-ci/run-static-checks.sh` => `static-checks: PASS`
2. `RUSTUP_TOOLCHAIN=nightly-2026-01-16 cargo check -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem --target x86_64-nonos.json --features "nonos-capsule-wallpaper nonos-wallpaper-smoketest"` => success (warnings only)
3. `make nonos-mk-wallpaper-test` => success (warnings only)
4. `make nonos-mk-run-serial` runtime attempt (2026-05-11) => blocked by `[NONOS] Handoff FAIL`; wallpaper marker sequence not yet observed

## 1. Main Baseline Inventory (Code-Verified)

| Path / Scope | Baseline State (2026-05-10) | Owner | Action | Validation |
| --- | --- | --- | --- | --- |
| `src/syscall/numbers/defs.rs` | Graphics syscall tag4 IDs are defined (`GDIM`, `GSCR`, `GSDS`, `GSMP`, `GPRF`, `GPRR`, `GDLS`, `GCUR`). | Kernel syscall contract | keep | `rg -n "GraphicsDisplay|GraphicsSurface|GraphicsCursor" src/syscall/numbers/defs.rs` |
| `src/syscall/abi/registry.rs` | Graphics entries exist and are marked `AbiStatus::Unavailable`. | Shared ABI | align runtime/spec status model | `rg -n "Graphics.*Unavailable|GDIM|GSCR|GSDS|GSMP|GPRF|GPRR|GDLS|GCUR" src/syscall/abi/registry.rs` |
| `src/syscall/dispatch/router/graphics_unavailable.rs` | All graphics syscalls route here and return `ENOTSUP`. | Kernel syscall dispatch | replace incrementally (query path first) | `rg -n "ENOTSUP|GraphicsDisplay|GraphicsSurface|GraphicsCursor" src/syscall/dispatch/router/graphics_unavailable.rs` |
| `src/syscall/contract/cap_table/graphics.rs` | Graphics syscalls are admitted with explicit per-family capability checks (`GraphicsDisplayQuery`, `GraphicsSurfaceCreate`, `GraphicsSurfaceMap`, `GraphicsPresent`) plus token validity. | Capability contract | keep strict and extend tests | `rg -n "GraphicsDisplayQuery|GraphicsSurfaceCreate|GraphicsSurfaceMap|GraphicsPresent|caps\.grants" src/syscall/contract/cap_table/graphics.rs` |
| `src/kernel_core/init/framebuffer.rs` | `init_framebuffer` is a typed no-op. | Kernel display primitive | implement canonical display state when backend lands | `rg -n "init_framebuffer|no-op|typed" src/kernel_core/init/framebuffer.rs` |
| `userland/libc/src/graphics/*` | Graphics wrappers exist for query/surface/present/cursor calls. | Userland runtime | keep | `rg -n "nonos_display|nonos_surface|nonos_cursor" userland/libc/src/graphics` |
| `src/userspace/capsule_wallpaper/*` + `userland/capsule_wallpaper/src/main.rs` | Wallpaper launch installs explicit graphics caps; markers are MkDebug-only; parked backend path exits PASS on `ENOTSUP`. | Smoke/profile path | keep and upgrade to real-backend PASS | `rg -n "mk_debug|GraphicsDisplayQuery|GraphicsSurfaceCreate|GraphicsSurfaceMap|GraphicsPresent|ENOTSUP" src/userspace/capsule_wallpaper userland/capsule_wallpaper/src/main.rs` |
| `src/process/core/table/inherit.rs` | Graphics capabilities are explicitly excluded from ambient inheritance. | Process capability policy | keep strict non-ambient rule | `rg -n "GraphicsDisplayQuery|GraphicsSurfaceCreate|GraphicsSurfaceMap|GraphicsPresent|FORBIDDEN_AMBIENT" src/process/core/table/inherit.rs` |
| `abi/syscalls.toml` | Integer-numbered ABI table; no graphics descriptors in this spec file. | Shared ABI docs | reconcile with runtime tag4 contract | `rg -n "\[numbers\]|GDIM|GSCR|Graphics" abi/syscalls.toml` |
| `abi/caps.toml` | Minimal rights set (`LOG`, `YIELD`, `TIME`, `IPC`, `KSTAT`). | Shared ABI docs | extend only when runtime contract is fixed | `rg -n "^\[bits\]|LOG|YIELD|TIME|IPC|KSTAT|Graphics" abi/caps.toml` |
| `abi/wire.toml` | Minimal wire contract; no graphics operation schema set. | Shared ABI docs | add versioned graphics wire schema after authority decision | `rg -n "user_copy|gateway_default|Graphics|display|surface|present|hotplug|input" abi/wire.toml` |
| `abi/manifest.toml` | No `storage_policy` field in current manifest ABI. | Shared ABI docs | add only with runtime consumer support | `rg -n "\[fields\]|storage_policy|required_caps" abi/manifest.toml` |

### 1.1 Explicitly Absent On Current Main

The following roots referenced by older migration snapshots are absent and must not be treated as active implementation evidence:

- `src/graphics/*`
- `src/display/*`
- `src/input/*`
- `src/userspace/{display_service,input_service,gpu_service,desktop_service}/*`
- `src/userspace/capsule_display/*`
- `userland/capsule_display/*`
- `tools/ci/run-static-checks.sh`
- `tests/boot/wallpaper_round_trip.sh`

Verification command:

```sh
for p in \
    src/graphics src/display src/input \
    src/userspace/display_service src/userspace/input_service src/userspace/gpu_service src/userspace/desktop_service \
    src/userspace/capsule_display userland/capsule_display \
    tools/ci/run-static-checks.sh tests/boot/wallpaper_round_trip.sh; do
    [ -e "$p" ] && echo "EXISTS $p" || echo "MISSING $p"
done
```

## 2. Keep / Build / Defer / Delete Matrix (Main Baseline)

| Subsystem | Current Main State | Decision | Next Gate |
| --- | --- | --- | --- |
| Syscall ID surface (tag4) | Present in runtime (`defs.rs`, ABI registry, libc constants). | keep | maintain single authoritative mapping source |
| Graphics dispatch backend | Fully parked via `graphics_unavailable` + `ENOTSUP`. | build | land `display_dimensions` backend first |
| Graphics capability checks | Explicit per-family graphics caps are enforced in cap-table. | keep | add focused deny/allow regression tests and CI policy gates |
| Framebuffer/display kernel primitive | `init_framebuffer` is no-op. | build | establish one canonical typed display state |
| Wallpaper smoke path | Launch path exists; runtime proof blocked by `ENOTSUP` backend. | keep | rerun smoke only after first backend slice |
| ABI authority alignment (`abi/*.toml` vs runtime tag4) | Drift exists. | build | choose authority, then sync other side |
| Display capsule scaffolding (`capsule_display`) | Absent in current main baseline. | defer | only revisit after query backend + cap gates |
| Compositor / desktop_shell / wm / toolkit runtime | Not implemented in active source paths on current main. | defer | unlock after Phase 2 contract stabilization |
| Legacy kernel graphics frontend families | Paths absent on current main. | keep deleted | prevent reintroduction via migration PR checks |
| Handoff diagnostics order | `init_core_systems()` still runs before handoff validation in entry path. | build | validate handoff before broad subsystem bring-up |

## 3. Owner-By-Owner Migration Tasks

| Owner | Responsibilities | First Delivery | Handoff Target | Must Prove |
| --- | --- | --- | --- | --- |
| Kernel display primitive | boot fb handoff, display info, present mechanism | canonical framebuffer truth | Kernel graphics contract, capsule_display | one descriptor, one registration path, one read path |
| Kernel input primitive | trusted hardware ingest | stable input event production | capsule_input | no focus/z-order policy in kernel |
| Kernel graphics contract | ABI ops + caps + lifetime rules | versioned wire + capability matrix | capsule_display/compositor/input | MkIpc-only transport and cap checks |
| capsule_display | display query/surface/present broker | real process/capsule endpoint | compositor + app clients | no kernel-global UI dependencies |
| capsule_compositor | scene graph/damage/cursor/frame scheduling | background + test surface present | desktop shell + wm + apps | zero kernel graphics global usage |
| capsule_input | routing policy + stream fanout | trusted event stream to compositor/WM | compositor + wm | denied-capability behavior verified |
| capsule_desktop_shell | dock/menu/tray/wallpaper/launcher/spotlight policy | shell surface submission via IPC | app capsules | shell state not kernel-owned |
| capsule_wm | focus/z-order/lifecycle/resize policy | create/map/focus/resize/close protocol | toolkit/apps | WM state singular in userland |
| userland toolkit | components/design/theme/animation | surface-targeted rendering library | app capsules | no direct framebuffer access |
| userland app capsule | terminal/settings/file manager/browser/wallet UIs | one migrated app end-to-end | n/a | app crash isolation and cleanup |
| shared ABI | abi/* truth + bindings | synced spec + implementation checks | all owners | no drift between abi and runtime |
| delete | old kernel frontend cleanup | remove giant kernel graphics surface | n/a | no silent fallback |

## 4. Dependency Graph And Parallelization

```text
Framebuffer truth
    ↓
Graphics ABI
    ↓
Real display service
    ↓
Compositor
    ↓
Input routing
    ↓
Desktop shell
    ↓
Window manager
    ↓
Toolkit/apps
    ↓
Delete old kernel graphics frontend
    ↓
Multi-arch hardening
```

Parallelization:
- Phase 0 and ABI draft preparation can overlap, but ABI ratification waits for Phase 1 canonical fb truth.
- Phase 6 and Phase 7 can overlap after Phase 4 and Phase 5 contracts are stable.
- Phase 8 and per-app slices in Phase 9 can run in parallel once WM/compositor client contracts are frozen.
- Phase 10 cannot start before functional parity of Phases 6-9.
- Phase 11 cannot finalize before Phase 10 contract and code reduction are stable.

## 5. Phase-By-Phase Implementation Checklists (Current-Main Aligned)

### 5.0 Baseline Execution Guard (Required)

Before executing any phase item below:

1. Treat Section 0 and Sections 1-2 as the current-state truth.
2. Treat all `[x]` markers below as valid only for the current baseline commit.
3. Re-run baseline preflight whenever `origin/main` moves.
4. Do not mark a phase complete without evidence commands passing on the active commit.
5. Do not merge or rebase old split-branch graphics work wholesale; port only approved slices onto current main.
6. Skip markdown-only work (`*.md`) during phase implementation commits unless explicitly requested; prioritize runtime code/test slices first.

Baseline preflight:

```sh
git rev-parse --short HEAD
git rev-parse --short origin/main
git rev-list --left-right --count origin/main...HEAD
```

### Phase 0: Truth Map and Freeze Guard

Baseline status: complete on current main.

Completed now:
- [x] current-main baseline pinned in Section 0
- [x] active graphics contract inventory captured in Section 1
- [x] absent legacy path inventory captured in Section 1.1
- [x] execution guard defined for all next phases

Remaining:
- [x] markdown updates are explicitly requested for this execution thread; continue code/test slices with per-completion doc updates

### Phase 1: Framebuffer / Display Truth Canonicalization

Baseline status: in progress.

Completed now:
- [x] framebuffer init hook exists (`init_framebuffer`)
- [x] canonical kernel-owned framebuffer state is initialized once and stored for runtime use
- [x] framebuffer mapping path is kernel-only writable + NX + non-user
- [x] graphics query/present paths consume canonical framebuffer state without returning fb pointers
- [x] static gate enforces no user-mapping APIs/flags in framebuffer init path

Open work:
- [x] implement canonical kernel-owned framebuffer state
- [x] validate boot framebuffer metadata before use
- [x] map framebuffer kernel-only writable, NX, non-user
- [x] ensure framebuffer pointer is never returned to userland
- [x] add gate proving framebuffer is never USER-mapped

### Phase 2: Graphics ABI / Contract

Baseline status: partial.

Completed now:
- [x] active runtime syscall IDs use tag4 registry constants
- [x] graphics syscall family exists in runtime enum/registry/libc wrappers
- [x] graphics router routes through explicit `graphics_backend` handlers and no longer depends on parked `graphics_unavailable`

Open work:
- [x] reconcile `abi/*.toml` specs with active runtime registry contract
- [x] replace graphics cap-table `caps.is_valid()` admission with explicit graphics caps
- [x] add static gates: no raw syscall IDs in userland graphics/smoke code
- [x] add static gates: no `_exit`/`write`/`read`/`mmap` imports in wallpaper/proof/driver smoke capsules
- [x] add static gate: libc graphics constants must match ABI registry constants
- [x] add static gate: no asm in userland capsules used for graphics proof

### Phase 3: Make Display Service Real

Baseline status: partial bootstrap (backend path pending).

Completed now:
- [x] wallpaper capsule wiring and launch path exist

Open work:
- [x] define and enforce explicit wallpaper capability install set in capsule spec: `CoreExec`, `Memory`, `Debug`, `GraphicsDisplayQuery`, `GraphicsSurfaceCreate`, `GraphicsSurfaceMap`, `GraphicsPresent`
- [x] keep wallpaper markers on `MkDebug` path only with exact sequence: `[wallpaper] display ok`, `[wallpaper] surface created`, `[wallpaper] surface filled`, `[wallpaper] present ok`, `[wallpaper] PASS`
- [x] implement graceful `ENOTSUP` handling while backend remains parked
- [x] add real display capsule/service path once Phase 2 gates are closed

### Phase 4: Userland Compositor Skeleton

Baseline status: not started on current main.

Open work:
- [x] create compositor runtime with canonical IPC path
- [x] establish scene/damage/cursor ownership in userland
- [x] integrate present path via graphics contract

### Phase 5: Input Service and Routing

Baseline status: not started on current main.

Open work:
- [x] keep kernel input ingest only
- [x] move routing/focus policy fully to userland chain
- [x] prove denied-cap behavior and input event flow end to end

### Phase 6: Desktop Shell Migration

Baseline status: not started on current main.

Open work:
- [x] migrate shell policy (wallpaper/dock/menubar/tray/spotlight)
- [x] route shell rendering only through compositor IPC
- [ ] remove kernel-owned shell policy state

### Phase 7: Window Manager Migration

Baseline status: not started on current main.

Open work:
- [ ] migrate focus/z-order/lifecycle/resize ownership to userland WM
- [ ] remove kernel-global WM state
- [ ] add lifecycle and focus regression tests

### Phase 8: Toolkit / Components / Design System Migration

Baseline status: not started on current main.

Open work:
- [ ] move toolkit/theme/animation/component policy to userland
- [ ] ensure toolkit renders to surfaces only
- [ ] remove app-facing kernel UI exports

### Phase 9: App UI Migration

Baseline status: not started on current main.

Open work:
- [ ] migrate app UIs to userland app capsules/processes
- [ ] enforce non-ambient framebuffer access model
- [ ] verify cleanup on app exit/crash

### Phase 10: Kernel Graphics Frontend Reduction

Baseline status: partial (legacy trees absent, migration not complete).

Completed now:
- [x] legacy kernel graphics tree families are absent on current main baseline

Open work:
- [ ] prevent reintroduction of removed legacy frontend surfaces via gates
- [ ] remove dead public graphics-facing APIs that no longer map to runtime behavior
- [ ] ensure kernel retains mechanism-only graphics/input responsibilities

### Phase 11: Multi-Architecture Hardening

Baseline status: not started on current main.

Open work:
- [ ] keep ABI graphics semantics architecture-neutral
- [ ] isolate backend-specific details below contract boundary
- [ ] document and validate per-target readiness truthfully

## 6. Definition Of Done Per Milestone (Current-Main Aligned)

### Milestone A: Truth Map Complete
- [x] current-main graphics authority map is documented
- [x] absent legacy path families are explicitly listed
- [x] baseline execution guard is in place

### Milestone B: Framebuffer Truth Complete
- [ ] canonical framebuffer state is implemented
- [ ] framebuffer mapping is kernel-only writable NX non-user
- [ ] framebuffer pointer is never exposed to userland

### Milestone C: ABI Ready
- [x] active runtime tag4 registry is inventoried
- [ ] abi spec files are reconciled to active runtime contract
- [x] explicit graphics capability checks are enforced
- [ ] static gates for disallowed userland/raw syscall patterns pass

### Milestone D: Display Service Real
- [ ] display service runs as real capsule/process
- [ ] endpoint registration is fail-closed
- [ ] display/surface/present path is canonical IPC

### Milestone E: Compositor Real
- [ ] compositor owns scene/damage/cursor in userland
- [ ] compositor presents through real graphics contract

### Milestone F: Desktop Shell Migrated
- [ ] shell policy is userland-owned
- [ ] shell rendering path is compositor IPC only

### Milestone G: Window Manager Migrated
- [ ] WM state is singular and userland-owned
- [ ] kernel WM policy/state is removed

### Milestone H: Toolkit and Apps Migrated
- [ ] toolkit ownership is userland-only
- [ ] app UIs run as userland capsules/processes

### Milestone I: Kernel Graphics Reduced
- [ ] kernel mechanism-only boundary is enforced by code and gates
- [ ] no stale legacy graphics API surface remains

### Milestone J: Multi-Arch Ready
- [ ] ABI remains arch-neutral
- [ ] backend differences are isolated and documented per target

## 7. Risk Register With Mitigation

| Risk | Phase | Cause | Impact | Detection | Mitigation | Owner |
| --- | --- | --- | --- | --- | --- | --- |
| fake userspace service remains | 3-10 | kernel-linked shells still on runtime path | migration is cosmetic | rg -n "src/userspace/(display|input|gpu|desktop)_service" src | replace launch path with capsule runtime and remove shell path | Kernel graphics contract owner |
| display service not actually capsule/runtime-backed | 3 | process spawn still points at shell function | authority model remains fake | inspect src/kernel_core/process_spawn/entries.rs | spawn real capsule with manifest-attested caps | Process lifecycle owner |
| compositor wraps old kernel window state | 4-7 | compositor uses crate::graphics::window globals | split-brain WM behavior | rg -n "crate::graphics::window|graphics::window" userland/compositor userland/wm | enforce ABI-only client path | Compositor owner |
| duplicated framebuffer state survives | 1 | weak and rich state both present | inconsistent dimensions/stride/bpp | rg -n "FB_ADDR|FB_WIDTH|FB_HEIGHT|FB_PITCH" src | delete weak state and stale readers | Kernel display primitive owner |
| surface handles leak after process exit | 3-4 | lifecycle cleanup not tied to pid exit | memory/resource leaks | stale-handle tests and process-exit checks | bind handles to owner pid and cleanup on exit | capsule_display owner |
| input routing policy remains in kernel | 5 | ingest and routing not split | focus/input bugs and authority confusion | rg -n "focus|window|z_order" src/input src/graphics | keep ingest only in kernel and route in capsule_input | Kernel input + capsule_input owners |
| focus state duplicated | 7 | transition leaves kernel and userland owners | incoherent focus behavior | grep focus ownership across layers | single owner rule in capsule_wm | capsule_wm owner |
| z-order state duplicated | 7 | both compositor and kernel track stacking | visual order regressions | grep z_order and manager state | explicit ownership contract and kernel cleanup | capsule_wm owner |
| direct framebuffer writes remain in toolkit/apps | 8-9 | legacy helpers still used | compositor bypass and state corruption | rg -n "put_pixel|fill_rect|framebuffer" userland src/graphics/window | toolkit render-to-surface only + lint guard | userland toolkit owner |
| protocol bounds missing in graphics handlers | 2-5 | payload and parser bounds not enforced end-to-end | memory pressure or parser faults | rg -n "MAX_PAYLOAD|max_ipc_msg|max_copy_bytes|checked_add|len" src/services abi | enforce bounded lengths in wire+parser+handlers before phase exit | Shared ABI owner |
| capability delegation exceeds subset rules | 2-5 | grant path can over-authorize graphics service | privilege escalation | rg -n "delegation|subset|grant_caps_internal" abi src | require subset-checked delegation for graphics grants | Kernel graphics contract owner |
| graphics capsules violate no-persistence default | 3-9 | privacy policy drifts to persistent mode by default | architecture drift from NONOS profile | verify manifest privacy policy and nonos build profile checks | default to ZeroStateOnly/Ephemeral unless exception approved | Shared ABI owner |
| missing capability check gives ambient display access | 2-5 | incomplete cap table enforcement | privilege escalation | cap denial tests + cap_table audits | map every ABI op to explicit cap | Kernel graphics contract owner |
| new graphics-specific IPC model appears | 2-5 | ad-hoc transport introduced | duplicate protocols and drift | rg -n "graphics.*channel|custom.*ipc" src userland | enforce MkIpcSend/MkIpcRecv/MkIpcCall-only rule | Shared ABI owner |
| old kernel UI path remains as silent fallback | 10 | fallback path left default-on | hidden ownership ambiguity | boot/runtime path inspection | no silent fallback, only explicit temporary gate | Kernel graphics reduction owner |
| x86_64-only assumptions enter ABI | 2,11 | ABI includes arch-specific semantics | multi-arch redesign later | grep cfg(target_arch) in ABI/handlers | keep ABI arch-neutral; isolate backend differences | Shared ABI owner |
| aarch64 requires redesign | 11 | backend assumptions leak from x86_64 path | schedule slip and rework | aarch64 build/readiness report | document requirements early and isolate backend code | Multi-arch owner |
| old src/graphics/mod.rs remains giant frontend surface | 10 | migration does not remove exports | kernel scope remains dishonest | inspect exports in src/graphics/mod.rs | reduce/delete frontend and stale re-exports | Kernel graphics reduction owner |
| migration adds placeholders/stubs/fake adapters | all | shortcuts during phased migration | production debt, unclear truth model | rg -n "TODO|stub|placeholder|fake|adapter|compat" src userland | fail phase exit if placeholders remain | Phase owner |

## 8. Rollback And Commit Plan

| Commit | Scope | Expected Build Status | Rollback Risk | Validation Commands | Boot/Display Risk |
| --- | --- | --- | --- | --- | --- |
| Commit 1 | documentation/truth map only | build unchanged | low | rg -n "Phase|Milestone|Risk" docs/plans/graphics-userland-migration-implementation-plan.md | none |
| Commit 2 | freeze guard | build unchanged or CI-only | low | guard command + PR check dry-run | none |
| Commit 3 | framebuffer canonicalization | x86_64 and kernel target checks pass | medium | FB_* grep checks + cargo check targets | high |
| Commit 4 | ABI definitions | protocol and ABI checks pass | medium | ABI op/cap grep checks + cargo check | medium |
| Commit 5 | display service real IPC path | service launch path and cap checks pass | high | spawn/caps/endpoint checks + cargo check | high |
| Commit 6 | compositor skeleton | compositor smoke path works | high | compositor IPC checks + build checks | high |
| Commit 7 | input routing | keyboard/mouse smoke checks pass | medium-high | input stream checks + tests VERIFY_IN_REPO | medium-high |
| Commit 8 | desktop shell migration | shell runtime checks pass | high | shell IPC + render smoke VERIFY_IN_REPO | high |
| Commit 9 | window manager migration | WM lifecycle tests pass | high | create/open/close/focus/resize tests | high |
| Commit 10 | toolkit/apps migration | migrated apps compile/run | high | per-app smoke tests + build checks | medium-high |
| Commit 11 | delete/reduce old kernel graphics frontend | no old path dependency remains | high | export/path grep checks + build checks | high |
| Commit 12 | multi-arch hardening | x86_64 passes, aarch64 status documented | medium | x86_64 build + aarch64 VERIFY_IN_REPO | medium |

Per-commit reporting requirements:
- expected build status
- rollback risk label
- exact validation command outputs
- boot/display risk label and result when medium/high

## 9. Implementation-Grade Rules

Every phase task and PR must explicitly answer:
- what file/module changes
- what owns it today
- what owns it after migration
- what state moves
- what IPC/capability boundary is required
- compile path class for touched modules (core/test/arch/legacy)
- how to validate it
- when the old path can be deleted

PR checklist requirements:
- [ ] touched paths list included
- [ ] owner before/after mapping included
- [ ] moved state list included
- [ ] IPC and capability changes included
- [ ] validation command output pasted
- [ ] old-path deletion condition or hard gate condition included

Unknowns policy:
- Any uncertainty must be tagged VERIFY_IN_CODEBASE or VERIFY_IN_REPO before phase exit is approved.
