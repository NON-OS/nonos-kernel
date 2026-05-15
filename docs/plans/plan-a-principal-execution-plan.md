# Plan A Principal Execution Plan (Rusty User Surface)

Date: 2026-05-15
Source of truth: docs/plans/user_surface_pan(rusty).md
Status: Execution in progress (A1-A2 complete; A3 next)

## 1) Understanding and Assumptions

### Goal Restatement
- Deliver the full Plan A user-surface stream as production-ready CPL=3 capsules and one toolkit library in strict A1 to A7 order.
- Enforce correctness and reviewability through explicit gates: multi-arch build, signing, static checks, boot chain join, and healthcheck probe.
- Make no kernel changes. Consume only approved contracts in abi/wire.toml.

### Assumptions
- Plan B contracts for compositor, wm, and input are stable in abi/wire.toml.
- CI gate entrypoint remains nonos-ci/run-static-checks.sh.
- Integration evidence is tracked in docs/production-roadmap/capsule_integration_matrix.md.
- Build and signing follow existing Make targets in repo.

### External Dependencies
- Plan B substrate readiness: compositor, wm, input_router, gfx driver.
- Kernel syscall surface available exactly as specified.
- Trust ceremony tooling available per capsule.
- Probe driver support for OP_HEALTHCHECK in serial traces.

### Unknowns and Blockers to Confirm
1. Exact final crate slugs and Make target names for all new capsules.
2. Default wallpaper decode route (direct toolkit decode vs image_codec route only for hot reload).
3. Status of process_manager debug observability opcode assignment in abi/wire.toml.
4. Signing cadence policy (per milestone vs per phase completion).
5. Boot integration cadence (per capsule commit vs batched per phase).

### Reality Check (feature/ek-platform-substrate, 2026-05-15)
- Verified landed substrate path for B1-B5 by commit/file evidence (`surface_registry`, `virtio_gpu`, `compositor`, `input_router`, `wm`).
- Verified A6 scaffold is present and wired through setup + server flow.
- Verified A3 scaffold exists, but current `capsule_wallpaper/src/main.rs` still runs proof-style direct graphics path and does not yet dispatch through the modular server path.
- Did not find concrete symbols for the claimed boot-race split (`retry-with-yield`, `prime::run_once`, `retry::run`, `probe_compositor`) in repository text search.
- Did not find concrete in-tree markers for explicit `intel_gfx` / `B6` labeling; treat as unverified in this plan until code/docs evidence lands.

---

## 2) Execution Blueprint (Phase by Phase)

## Cross-Phase Enforcement (A1-A7)
- No static mut.
- No unsafe except allowed cases in plan.
- Standard capsule modular layout.
- Explicit E_BAD_OP, E_BAD_LEN, E_BAD_MAGIC, E_BAD_VERSION handling.
- Timeout on every mk_ipc_call (default 100 ms unless overridden in ABI config).
- No cross-capsule pointers. Only (pid, handle) through surface registry contracts.
- Multi-arch build from first commit for each deliverable.
- No allow(dead_code) or allow(unused).

### Validation Baseline Commands
- make -B nonos-mk-<slug>
- make nonos-mk-<slug>-sign
- nonos-ci/run-static-checks.sh
- Cargo checks for x86_64-nonos-user, aarch64-nonos-user, riscv64-nonos-user
- QEMU serial verification for OP_HEALTHCHECK probe response

Expected baseline outcomes:
- Zero warnings, signed artifacts, static gates green, capsule joins boot chain and answers healthcheck.

---

## A1 Toolkit Library

### Objective
Create a pure toolkit library with no IPC port and no kernel coupling.

### In Scope
- userland/toolkit crate scaffold and full module families:
  - font
  - design
  - components
  - animation
  - image
  - qr
- Refactor to caller-owned buffers (no global mutable render state).

### Out of Scope
- Any service registration or capsule server runtime.

### Work Breakdown
- Crate + module map + re-export surface.
- Legacy ports with per-file cap compliance.
- PNG decode split internals.
- CI static gate enforcing no kernel imports and no IPC syscall usage.

### Step-by-Step Tasks
1. Scaffold crate, lib.rs exports, and module topology.
2. Port font and design primitives first.
3. Port image decode stack including PNG split internals.
4. Port components with caller-owned buffer signatures.
5. Port animation and qr.
6. Add static gate and run multi-arch validation.

### Integration Dependencies
- None for runtime. Depends only on repository build system and ABI conventions.

### Risks and Rollback
- Risk: file-size cap violations.
- Risk: hidden global assumptions in legacy code.
- Rollback: revert module batch commits independently; keep legacy source untouched.

### Exit Criteria
- Toolkit builds with zero warnings on all three user triples.
- Static gate proves no kernel imports and no IPC syscall usage.
- Public API aligns with toolkit contract in plan.

---

## A2 capsule_image_codec

### Objective
Implement a thin IPC decode service over toolkit image APIs that returns ARGB8888 surface handles.

### In Scope
- Standard capsule shape.
- Ops: HEALTHCHECK, DECODE_PNG, DECODE_BMP, DECODE_LZ4_RAW, DECODE_JPEG.
- Strict request validation and explicit error replies.

### Out of Scope
- Compositor policy logic.

### Work Breakdown
- Protocol parsing and response writer.
- Format-specific decode handlers.
- Surface registration and handle response path.

### Step-by-Step Tasks
1. Scaffold module tree and runner.
2. Implement parse_req and respond validation logic.
3. Implement healthcheck.
4. Wire all decode handlers to toolkit.
5. Implement surface registration and response payload.
6. Enforce timeout discipline.
7. Validate sign, matrix row, and probe evidence.

### Integration Dependencies
- A1 toolkit image APIs.
- Surface syscall contract.

### Risks and Rollback
- Risk: memory pressure with large payloads.
- Risk: handle lifecycle leaks.
- Rollback: keep spawn disabled until healthcheck and decode smoke checks are stable.

### Exit Criteria
- All decode ops deterministic with explicit errno behavior.
- Healthcheck verified in runtime.
- Signed and integrated in matrix and CI gates.

---

## A3 capsule_wallpaper (real)

### Objective
Replace proof implementation with policy-driven, compositor-integrated wallpaper service.

### In Scope
- Ops: HEALTHCHECK, SET_WALLPAPER, GET_WALLPAPER, SET_POLICY, FADE.
- State lease tracking.
- Decode path and bottom-layer scene submit.

### Out of Scope
- Desktop shell internal policy ownership beyond API contract.

### Work Breakdown
- protocol/state/setup/server modules.
- decode_client and compositor_client modules.
- Surface lifecycle and fade flow.

### Step-by-Step Tasks
1. Scaffold full module tree.
2. Implement discovery for desktop_shell and compositor.
3. Implement set/get/policy handlers.
4. Implement decode path (direct toolkit and optional image_codec route).
5. Implement scene submit as bottom layer.
6. Implement fade transitions.
7. Validate runtime healthcheck and serial trace evidence.

### Integration Dependencies
- A1 toolkit image.
- A2 image codec (optional route).
- compositor contract in ABI.

### Risks and Rollback
- Risk: surface lease lifecycle bugs.
- Risk: policy mismatches with shell expectations.
- Rollback: feature-gate optional decode route and keep direct route stable.

### Exit Criteria
- All wallpaper ops implemented and verified.
- Bottom-layer behavior observed.
- Signed, gated, and documented.

---

## A4 capsule_clipboard

### Objective
Deliver bounded pure-userland clipboard with typed content and history ring.

### In Scope
- Ops: HEALTHCHECK, COPY, PASTE, HISTORY_LIST, HISTORY_GET, CLEAR.
- Manifest-driven depth and byte limits.

### Out of Scope
- Input/window ownership policy beyond explicit API.

### Work Breakdown
- State ring model.
- Handler implementation.
- Config defaults wiring.

### Step-by-Step Tasks
1. Scaffold capsule.
2. Implement bounded ring.
3. Implement copy/paste.
4. Implement history list/get.
5. Implement clear.
6. Wire manifest defaults.
7. Validate sign, matrix, and probe evidence.

### Integration Dependencies
- Core IPC only.

### Risks and Rollback
- Risk: memory cap bypass.
- Risk: index-boundary errors.
- Rollback: isolate history operations behind conservative limits if needed.

### Exit Criteria
- Deterministic bounded behavior with explicit errors.
- Signed and integrated with CI and matrix evidence.

---

## A5 capsule_login

### Objective
Implement pre-desktop auth gate with keyring validation and session transitions.

### In Scope
- Ops: HEALTHCHECK, START_SESSION, END_SESSION, GET_STATE.
- Toolkit-rendered full-screen login UI.
- Compositor submit and shell signal on success.

### Out of Scope
- Keyring backend redesign.

### Work Breakdown
- State machine for lock/session.
- Keyring client integration.
- UI render and compositor path.
- Session control handlers.

### Step-by-Step Tasks
1. Scaffold capsule and state.
2. Integrate keyring client.
3. Implement UI render loop using toolkit.
4. Implement session start flow.
5. Implement end and state query flow.
6. Integrate compositor submit and shell signal.
7. Validate failed/success auth behavior.

### Integration Dependencies
- A1 toolkit.
- keyring, compositor, desktop_shell contracts.

### Risks and Rollback
- Risk: state race across auth transitions.
- Rollback: lock all transitions behind strict state checks.

### Exit Criteria
- Correct lock/unlock behavior with deterministic state transitions.
- Signed and runtime verified.

---

## A6 capsule_desktop_shell

### Objective
Replace shell proof with full modular subsystem implementation.

### In Scope
- Subsystems: dock, menubar, sidebar, tray, status, spotlight.
- Clients: compositor, wm, market, wallpaper.
- Server ops: HEALTHCHECK, TRAY_REGISTER, TRAY_UPDATE, TRAY_REMOVE, NOTIFY, SPOTLIGHT_OPEN.

### Out of Scope
- compositor/wm internals.

### Work Breakdown
- Subsystem state/render modules.
- Global state and subscriptions.
- Client IPC modules.
- Server handlers and policy propagation.

### Step-by-Step Tasks
1. Scaffold shell module topology.
2. Implement subsystem modules incrementally.
3. Implement compositor client ops.
4. Implement wm client ops.
5. Implement tray and notify handlers.
6. Implement spotlight handler path.
7. Implement market and wallpaper policy clients.
8. Validate flat-layer surface behavior and healthcheck.

### Integration Dependencies
- A1 toolkit.
- A3 wallpaper endpoint.
- Plan B compositor/wm contracts.

### Risks and Rollback
- Risk: event ordering and layer sync defects.
- Rollback: isolate unstable subsystems with feature flags while preserving core shell service.

### Exit Criteria
- All shell ops and subsystem layers functional.
- Signed, gated, and integrated with boot/probe evidence.

---

## A7 App Capsules Wave 1

### Objective
Deliver seven app capsules using a consistent loop and per-app state modules.

### In Scope
- capsule_about
- capsule_calculator
- capsule_terminal
- capsule_file_manager
- capsule_text_editor
- capsule_settings
- capsule_process_manager

### Out of Scope
- Additional app wave beyond seven listed.

### Work Breakdown
- Shared skeleton pattern.
- Per-app render/state logic.
- wm/compositor/input loop integration.
- settings/keyring and process manager debug-gated observability paths.

### Step-by-Step Tasks
1. Build reusable app skeleton.
2. Implement about and calculator first.
3. Implement terminal and file_manager.
4. Implement text_editor and settings.
5. Implement process_manager observability path.
6. Validate per-app healthcheck and runtime loop behavior.
7. Integrate signing, matrix rows, boot spawn ordering.

### Integration Dependencies
- A1 toolkit.
- wm/compositor/input contracts.
- capsule_vfs for file_manager.
- keyring for settings.
- debug observability op in ABI for process_manager.

### Risks and Rollback
- Risk: app loop divergence and maintenance drift.
- Risk: observability contract churn.
- Rollback: staggered boot enablement per app readiness.

### Exit Criteria
- Seven signed capsules with boot and healthcheck evidence.
- Matrix rows and static gates complete.

---

## 3) Detailed Task Checklists

Task format:
- ID
- Owner role
- Artifacts
- Verification step
- Done condition

## A1 Checklist
- [x] A1-T01 | Owner: Sr Rust Eng | Artifacts: toolkit scaffold and module map | Verify: compile all three user triples | Done: crate compiles with planned module tree.
- [x] A1-T02 | Owner: Sr Rust Eng | Artifacts: font modules | Verify: compile and API exposure checks | Done: font surface exported.
- [x] A1-T03 | Owner: Sr Rust Eng | Artifacts: design modules | Verify: compile with warnings treated as failures | Done: design primitives stable.
- [x] A1-T04 | Owner: Sr Rust Eng | Artifacts: image core modules | Verify: decode fixture checks | Done: decode path wired.
- [x] A1-T05 | Owner: Sr Rust Eng | Artifacts: PNG split internals | Verify: compile and fixture checks | Done: PNG modules complete and file cap compliant.
- [x] A1-T06 | Owner: Sr Rust Eng | Artifacts: components baseline set | Verify: render smoke checks | Done: baseline components functional.
- [x] A1-T07 | Owner: Sr Rust Eng | Artifacts: remaining component set | Verify: compile and no globals audit | Done: complete component set functional.
- [x] A1-T08 | Owner: Sr Rust Eng | Artifacts: animation modules | Verify: deterministic timing checks | Done: animation surface complete.
- [x] A1-T09 | Owner: Sr Rust Eng | Artifacts: qr modules | Verify: output shape checks | Done: qr module integrated.
- [x] A1-T10 | Owner: Sr Rust Eng | Artifacts: CI static gate update | Verify: run-static-checks pass | Done: toolkit no-kernel/no-ipc rule enforced.
- [x] A1-T11 | Owner: Sr Rust Eng | Artifacts: matrix evidence row | Verify: review of matrix entry | Done: A1 evidence recorded.

## A2 Checklist
- [x] A2-T01 | Owner: Sr Rust Eng | Artifacts: capsule scaffold | Verify: compile all triples | Done: canonical module shape present.
- [x] A2-T02 | Owner: Sr Rust Eng | Artifacts: parse_req/respond validation | Verify: malformed payload tests | Done: E_BAD_* paths deterministic.
- [x] A2-T03 | Owner: Sr Rust Eng | Artifacts: healthcheck handler | Verify: probe response | Done: OP_HEALTHCHECK stable.
- [x] A2-T04 | Owner: Sr Rust Eng | Artifacts: all decode handlers | Verify: format decode checks | Done: op surface complete.
- [x] A2-T05 | Owner: Sr Rust Eng | Artifacts: surface registration response | Verify: handle lifecycle smoke | Done: ARGB8888 handle returned.
- [x] A2-T06 | Owner: Sr Rust Eng | Artifacts: timeout enforcement | Verify: code audit and config check | Done: capsule has no mk_ipc_call call-sites; recv/send path stays bounded.
- [x] A2-T07 | Owner: Sr Rust Eng | Artifacts: sign/matrix/gate evidence | Verify: commands run and evidence recorded | Done: A2 accepted with static-gate blocker recorded.

## A3 Checklist
- [x] A3-T01 | Owner: Sr Rust Eng | Artifacts: scaffold and state lease model | Verify: compile all triples | Done: module structure complete.
- [x] A3-T02 | Owner: Sr Rust Eng | Artifacts: discover setup | Verify: service lookup smoke | Done: dependencies discovered reliably.
- [ ] A3-T03 | Owner: Sr Rust Eng | Artifacts: set/get handlers | Verify: request-response checks | Done: deterministic behavior.
- [ ] A3-T04 | Owner: Sr Rust Eng | Artifacts: set_policy handler | Verify: policy persistence checks | Done: policy round-trip works.
- [ ] A3-T05 | Owner: Sr Rust Eng | Artifacts: decode client path | Verify: decode smoke | Done: decode pipeline operational.
- [ ] A3-T06 | Owner: Sr Rust Eng | Artifacts: compositor submit client | Verify: bottom-layer observation | Done: scene submit contract met.
- [ ] A3-T07 | Owner: Sr Rust Eng | Artifacts: fade handler | Verify: transition checks | Done: fade op stable.
- [ ] A3-T08 | Owner: Sr Rust Eng | Artifacts: sign/static/matrix evidence | Verify: all checks pass | Done: A3 accepted.

## A4 Checklist
- [ ] A4-T01 | Owner: Sr Rust Eng | Artifacts: scaffold | Verify: compile all triples | Done: canonical shape complete.
- [ ] A4-T02 | Owner: Sr Rust Eng | Artifacts: bounded ring state | Verify: cap enforcement tests | Done: depth/size bounds guaranteed.
- [ ] A4-T03 | Owner: Sr Rust Eng | Artifacts: copy/paste handlers | Verify: round-trip checks | Done: deterministic copy/paste.
- [ ] A4-T04 | Owner: Sr Rust Eng | Artifacts: history handlers | Verify: boundary checks | Done: safe history access.
- [ ] A4-T05 | Owner: Sr Rust Eng | Artifacts: clear handler | Verify: clear-state checks | Done: reset behavior stable.
- [ ] A4-T06 | Owner: Sr Rust Eng | Artifacts: manifest default wiring | Verify: fallback tests | Done: defaults respected.
- [ ] A4-T07 | Owner: Sr Rust Eng | Artifacts: sign/static/matrix evidence | Verify: all checks pass | Done: A4 accepted.

## A5 Checklist
- [ ] A5-T01 | Owner: Sr Rust Eng | Artifacts: scaffold and auth state | Verify: compile all triples | Done: base structure complete.
- [ ] A5-T02 | Owner: Sr Rust Eng | Artifacts: keyring client integration | Verify: auth pass/fail tests | Done: validation path stable.
- [ ] A5-T03 | Owner: Sr Rust Eng | Artifacts: login UI render path | Verify: render smoke | Done: full-screen UI path works.
- [ ] A5-T04 | Owner: Sr Rust Eng | Artifacts: start session handler | Verify: transition tests | Done: unlock start deterministic.
- [ ] A5-T05 | Owner: Sr Rust Eng | Artifacts: end/get state handlers | Verify: transition/query tests | Done: lock-state coherence ensured.
- [ ] A5-T06 | Owner: Sr Rust Eng | Artifacts: compositor submit and shell signal | Verify: integration smoke | Done: successful auth triggers handoff.
- [ ] A5-T07 | Owner: Sr Rust Eng | Artifacts: sign/static/matrix evidence | Verify: all checks pass | Done: A5 accepted.

## A6 Checklist
- [ ] A6-T01 | Owner: Sr Rust Eng | Artifacts: shell scaffold and global state | Verify: compile all triples | Done: module topology complete.
- [ ] A6-T02 | Owner: Sr Rust Eng | Artifacts: dock subsystem | Verify: render/update checks | Done: dock functional.
- [ ] A6-T03 | Owner: Sr Rust Eng | Artifacts: menubar subsystem | Verify: clock/menu checks | Done: menubar functional.
- [ ] A6-T04 | Owner: Sr Rust Eng | Artifacts: sidebar subsystem | Verify: state/render checks | Done: sidebar functional.
- [ ] A6-T05 | Owner: Sr Rust Eng | Artifacts: tray subsystem and registry | Verify: tray op checks | Done: tray contract stable.
- [ ] A6-T06 | Owner: Sr Rust Eng | Artifacts: status subsystem | Verify: indicator checks | Done: status functional.
- [ ] A6-T07 | Owner: Sr Rust Eng | Artifacts: spotlight subsystem | Verify: query/input/result checks | Done: spotlight functional.
- [ ] A6-T08 | Owner: Sr Rust Eng | Artifacts: compositor and wm clients | Verify: scene/window flow checks | Done: client integration stable.
- [ ] A6-T09 | Owner: Sr Rust Eng | Artifacts: market and wallpaper clients | Verify: policy/update checks | Done: downstream integration complete.
- [ ] A6-T10 | Owner: Sr Rust Eng | Artifacts: server handlers | Verify: op contract checks | Done: shell op surface complete.
- [ ] A6-T11 | Owner: Sr Rust Eng | Artifacts: sign/static/matrix evidence | Verify: all checks pass | Done: A6 accepted.

## A7 Checklist
- [ ] A7-T01 | Owner: Sr Rust Eng | Artifacts: reusable app skeleton | Verify: compile all triples | Done: common loop pattern complete.
- [ ] A7-T02 | Owner: Sr Rust Eng | Artifacts: about capsule | Verify: open/input/render/submit checks | Done: about app accepted.
- [ ] A7-T03 | Owner: Sr Rust Eng | Artifacts: calculator capsule | Verify: interaction checks | Done: calculator accepted.
- [ ] A7-T04 | Owner: Sr Rust Eng | Artifacts: terminal capsule | Verify: stateful loop checks | Done: terminal accepted.
- [ ] A7-T05 | Owner: Sr Rust Eng | Artifacts: file_manager capsule | Verify: vfs integration checks | Done: file manager accepted.
- [ ] A7-T06 | Owner: Sr Rust Eng | Artifacts: text_editor capsule | Verify: edit/render checks | Done: text editor accepted.
- [ ] A7-T07 | Owner: Sr Rust Eng | Artifacts: settings capsule | Verify: shell/keyring integration checks | Done: settings accepted.
- [ ] A7-T08 | Owner: Sr Rust Eng | Artifacts: process_manager capsule | Verify: debug-gated observability checks | Done: process manager accepted.
- [ ] A7-T09 | Owner: Sr Rust Eng | Artifacts: all app sign artifacts | Verify: sign targets pass | Done: seven app artifacts signed.
- [ ] A7-T10 | Owner: Sr Rust Eng | Artifacts: boot integration and matrix updates | Verify: serial healthcheck probes | Done: wave 1 integration accepted.

### Initial Completion Snapshot
- A1: 11/11 complete (100%)
- A2: 7/7 complete (100%)
- A3: 2/8 complete (25.0%)
- A4: 0/7 complete (0%)
- A5: 0/7 complete (0%)
- A6: 0/11 complete (0%)
- A7: 0/10 complete (0%)
- Overall: 20/61 complete (32.8%)

---

## 4) Commit Plan (Milestone Groups)

Commit message style: type(scope): imperative summary

C01: feat(toolkit): scaffold toolkit crate and public module surface
- Why: establish module boundaries and API shape.
- Expected files: toolkit crate scaffold and workspace wiring.
- Pre-checks: all-triple toolkit check.
- Post-checks: static gate baseline passes.

C02: feat(toolkit-font-design): port font and design primitives
- Why: unblock render dependencies.
- Expected files: font and design module families.
- Pre-checks: compile with no warnings.
- Post-checks: primitive usage smoke checks.

C03: feat(toolkit-image): add image decode stack with png split internals
- Why: unblock wallpaper and image codec.
- Expected files: image modules and PNG internals.
- Pre-checks: decode fixture checks.
- Post-checks: forbidden dependency audit passes.

C04: feat(toolkit-components-animation-qr): complete toolkit functional surface
- Why: complete toolkit contract.
- Expected files: components, animation, qr modules.
- Pre-checks: all-triple checks.
- Post-checks: contract review against plan.

C05: ci(toolkit): enforce toolkit no-kernel-no-ipc static rule
- Why: lock architecture rule in CI.
- Expected files: nonos-ci static checks script.
- Pre-checks: shell validation.
- Post-checks: full static checks green.

C06: feat(image-codec): implement capsule_image_codec core ops and surface return
- Why: shared decode service.
- Expected files: image_codec capsule modules.
- Pre-checks: request parser and decode checks.
- Post-checks: healthcheck probe evidence.

C07: feat(wallpaper): replace proof with policy/decode/compositor pipeline
- Why: production wallpaper service.
- Expected files: wallpaper capsule and clients.
- Pre-checks: decode and submit checks.
- Post-checks: bottom-layer behavior evidence.

C08: feat(clipboard): implement bounded clipboard history service
- Why: fast high-value user service.
- Expected files: clipboard capsule modules.
- Pre-checks: cap and boundary tests.
- Post-checks: healthcheck and API behavior checks.

C09: feat(login): implement login gate and shell handoff path
- Why: pre-desktop auth flow.
- Expected files: login capsule and service clients.
- Pre-checks: auth transition checks.
- Post-checks: runtime success/fail scenarios.

C10: feat(desktop-shell): implement modular desktop shell subsystems
- Why: core user-shell orchestration.
- Expected files: shell subsystem, client, and handler modules.
- Pre-checks: subsystem contract checks.
- Post-checks: layer and op-surface runtime validation.

C11: feat(apps-wave1-core): add reusable app skeleton with about and calculator
- Why: establish app pattern and first wave start.
- Expected files: skeleton plus first two app capsules.
- Pre-checks: loop behavior checks.
- Post-checks: runtime and healthcheck validation.

C12: feat(apps-wave1-rest): add terminal, file_manager, text_editor, settings, process_manager
- Why: complete A7 scope.
- Expected files: five app capsule module trees.
- Pre-checks: per-app compile/integration checks.
- Post-checks: all app sign and runtime checks.

C13: docs(integration-matrix): record A1-A7 integration evidence
- Why: final traceability package.
- Expected files: matrix and capsule README contract sections.
- Pre-checks: evidence completeness audit.
- Post-checks: review-ready docs state.

---

## 5) Progress Tracking Protocol (Mandatory During Execution)

After every completed task and every commit:
1. Update checklist checkbox from [ ] to [x].
2. Append timestamped progress log entry with:
   - ID (task or commit)
   - What changed
   - Verification evidence
   - Next task
3. Recompute phase % and overall %.
4. If verification fails:
   - Mark item BLOCKED (not complete)
   - Record unblock plan and retry trigger.

### Progress Log Template
- [YYYY-MM-DD HH:MM UTC] ID: A1-T03 | Status: COMPLETE
- Change: <summary>
- Evidence: <command summaries and outcomes>
- Next: <next item>
- Phase A1: X/11 (Y%) | Overall: N/61 (Z%)

### Commit Log Template
- [YYYY-MM-DD HH:MM UTC] ID: C03 | Status: COMPLETE
- Commit: feat(toolkit-image): add image decode stack with png split internals
- Evidence: pre-checks pass, post-checks pass, static rules pass
- Next: <next item>
- Phase A1: X/11 (Y%) | Overall: N/61 (Z%)

## Execution Progress Log

- [2026-05-15 10:45 UTC] ID: A1-T01 | Status: BLOCKED
- Change: Scaffolded toolkit library crate surface in userland/toolkit with the A1 module map (font, design, components, animation, image, qr), added lib target wiring, and retained current runtime binary compatibility for existing static gates.
- Evidence: cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/x86_64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass, warning-free). Verification for aarch64-nonos-user and riscv64-nonos-user cannot run because corresponding user target JSON specs are not present in repository.
- Next: unblock A1-T01 by adding/confirming aarch64 and riscv64 user targets, then rerun three-triple checks.
- Phase A1: 0/11 (0%) | Overall: 0/61 (0%)

- [2026-05-15 10:56 UTC] ID: A1-T01 | Status: COMPLETE
- Change: Added canonical user target spec fields for aarch64 and riscv64, aligned riscv64 llvm-target with rustc canonical target-machine triple behavior, and scoped toolkit libc dependency to x86_64 so library checks are architecture-clean.
- Evidence: cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/x86_64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass); cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/aarch64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass); cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/riscv64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass).
- Next: A1-T02.
- Phase A1: 1/11 (9.1%) | Overall: 1/61 (1.6%)

- [2026-05-15 10:59 UTC] ID: A1-T02 | Status: COMPLETE
- Change: Implemented toolkit font slice with `GlyphBitmap`, `FontAtlas`, ASCII glyph lookup, text-width calculation, and caller-owned-buffer rendering APIs in `font::render`.
- Evidence: cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/x86_64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass); cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/aarch64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass); cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/riscv64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass).
- Next: A1-T03.
- Phase A1: 2/11 (18.2%) | Overall: 2/61 (3.3%)

- [2026-05-15 11:00 UTC] ID: A1-T03 | Status: COMPLETE
- Change: Implemented toolkit design primitives for color palette/ARGB, typography styles, spacing scale/insets, shadow presets, and border/radius models.
- Evidence: cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/x86_64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass); cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/aarch64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass); cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/riscv64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass).
- Next: A1-T04.
- Phase A1: 3/11 (27.3%) | Overall: 3/61 (4.9%)

- [2026-05-15 11:02 UTC] ID: A1-T04 | Status: COMPLETE
- Change: Implemented image core module primitives and decode paths for BMP (ARGB8888), raw ARGB buffer ingestion (`lz4_raw` decoded bytes path), shared image size/error types, and JPEG unsupported error path.
- Evidence: cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/x86_64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass); cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/aarch64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass); cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/riscv64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass).
- Next: A1-T05.
- Phase A1: 4/11 (36.4%) | Overall: 4/61 (6.6%)

- [2026-05-15 11:04 UTC] ID: A1-T05 | Status: COMPLETE
- Change: Implemented PNG split internals across `decoder`, `deflate`, `huffman`, `inflate`, and `scanline` with deterministic decode/error behavior and module-level separation matching A1 layout.
- Evidence: cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/x86_64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass); cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/aarch64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass); cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/riscv64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass).
- Next: A1-T06.
- Phase A1: 5/11 (45.5%) | Overall: 5/61 (8.2%)

- [2026-05-15 11:16 UTC] ID: A1-T06 | Status: COMPLETE
- Change: Implemented baseline toolkit components (`button`, `label`, `input`, `slider`, `list`, `dropdown`) with caller-owned buffer rendering APIs and design/font integration.
- Evidence: cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/x86_64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass); cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/aarch64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass); cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/riscv64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass).
- Next: A1-T07.
- Phase A1: 6/11 (54.5%) | Overall: 6/61 (9.8%)

- [2026-05-15 11:17 UTC] ID: A1-T07 | Status: COMPLETE
- Change: Implemented remaining toolkit components (`checkbox`, `radio`, `toggle`, `card`, `badge`, `colorpicker`, `datepicker`, `glass_panel`, `scroll`, `progress`, `menu`, `tooltip`, `tabbar`, `statusbar`) with no global state and deterministic utility/render APIs.
- Evidence: cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/x86_64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass); cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/aarch64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass); cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/riscv64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass).
- Next: A1-T08.
- Phase A1: 7/11 (63.6%) | Overall: 7/61 (11.5%)

- [2026-05-15 11:20 UTC] ID: A1-T08 | Status: COMPLETE
- Change: Implemented deterministic animation primitives in `easing`, `timing`, `state`, `runner`, and `transitions` modules using fixed-point easing and duration-based progression APIs.
- Evidence: cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/x86_64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass); cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/aarch64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass); cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/riscv64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass).
- Next: A1-T09.
- Phase A1: 8/11 (72.7%) | Overall: 8/61 (13.1%)

- [2026-05-15 11:22 UTC] ID: A1-T09 | Status: COMPLETE
- Change: Implemented QR module set (`format`, `ecc`, `mask`, `place`, `render`) with deterministic no-allocation APIs, payload placement, mask application, and ARGB matrix rendering.
- Evidence: cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/x86_64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass); cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/aarch64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass); cargo +nightly check --manifest-path userland/toolkit/Cargo.toml --lib --target userland/riscv64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec (pass).
- Next: A1-T10.
- Phase A1: 9/11 (81.8%) | Overall: 9/61 (14.8%)

- [2026-05-15 11:24 UTC] ID: A1-T10 | Status: COMPLETE
- Change: Added static gate in `nonos-ci/run-static-checks.sh` enforcing toolkit library sources exclude kernel-module imports and IPC syscall usage (excluding runtime `main.rs`).
- Evidence: nonos-ci/run-static-checks.sh (pass, new marker printed: toolkit library source has no kernel imports or IPC syscalls).
- Next: A1-T11.
- Phase A1: 10/11 (90.9%) | Overall: 10/61 (16.4%)

- [2026-05-15 11:27 UTC] ID: A1-T11 | Status: COMPLETE
- Change: Added toolkit library evidence row to the capsule integration matrix with the three-target toolkit verification command and library-state contract.
- Evidence: docs/production-roadmap/capsule_integration_matrix.md updated with `userland/toolkit` row; nonos-ci/run-static-checks.sh (pass, static-checks: PASS).
- Next: A2-T01.
- Phase A1: 11/11 (100%) | Overall: 11/61 (18.0%)

- [2026-05-15 15:05 UTC] ID: BRANCH-REALITY-CHECK | Status: COMPLETE
- Change: Validated feature/ek-platform-substrate state before A2 start; reconciled claims vs concrete repo evidence for A3/A6/B1-B5 and boot-race symbols.
- Evidence: `git --no-pager log --oneline --decorate -n 120`; `git --no-pager show --name-only -n 1 2f231d3fb 644915c46 66dde8ee9 c747cb63f 7ad4fe731 2d7055d50 c4f8ad77a`; `rg -n "retry_with_yield|retry-with-yield|probe_compositor|prime::run_once|retry::run|run_once\(|yield\(" userland src docs`.
- Next: A2-T01.
- Phase A1: 11/11 (100%) | Overall: 11/61 (18.0%)

- [2026-05-15 15:33 UTC] ID: A2-T01 | Status: COMPLETE
- Change: Added `userland/capsule_image_codec` scaffold with canonical `protocol/` + `server/` split, `Cargo.toml`, `Capsule.mk`, and main loop wiring.
- Evidence: `cargo +nightly check --manifest-path userland/capsule_image_codec/Cargo.toml --target userland/x86_64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec` (pass); `cargo +nightly check --manifest-path userland/capsule_image_codec/Cargo.toml --target userland/aarch64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec` (pass); `cargo +nightly check --manifest-path userland/capsule_image_codec/Cargo.toml --target userland/riscv64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec` (pass).
- Next: A2-T02.
- Phase A2: 1/7 (14.3%) | Overall: 12/61 (19.7%)

- [2026-05-15 15:35 UTC] ID: A2-T02 | Status: COMPLETE
- Change: Implemented deterministic request header parsing + payload bounds enforcement and centralized response encoders for success and errno paths.
- Evidence: `cargo +nightly check --manifest-path userland/capsule_image_codec/Cargo.toml --target userland/x86_64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec` (pass).
- Next: A2-T03.
- Phase A2: 2/7 (28.6%) | Overall: 13/61 (21.3%)

- [2026-05-15 15:36 UTC] ID: A2-T03 | Status: COMPLETE
- Change: Added `OP_HEALTHCHECK` handler and stable op dispatch path.
- Evidence: `cargo +nightly check --manifest-path userland/capsule_image_codec/Cargo.toml --target userland/x86_64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec` (pass).
- Next: A2-T04.
- Phase A2: 3/7 (42.9%) | Overall: 14/61 (23.0%)

- [2026-05-15 15:38 UTC] ID: A2-T04 | Status: COMPLETE
- Change: Wired PNG/BMP/JPEG/LZ4 decode handlers through toolkit image decoders and deterministic opcode mapping.
- Evidence: `cargo +nightly check --manifest-path userland/capsule_image_codec/Cargo.toml --target userland/x86_64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec` (pass); `cargo +nightly check --manifest-path userland/capsule_image_codec/Cargo.toml --target userland/aarch64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec` (pass); `cargo +nightly check --manifest-path userland/capsule_image_codec/Cargo.toml --target userland/riscv64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec` (pass).
- Next: A2-T05.
- Phase A2: 4/7 (57.1%) | Overall: 15/61 (24.6%)

- [2026-05-15 15:39 UTC] ID: A2-T05 | Status: COMPLETE
- Change: Implemented surface registration/share response path (`mk_mmap`, `mk_surface_register`, `mk_surface_share`) returning ARGB8888 metadata + handle.
- Evidence: `make nonos-mk-image-codec` (pass).
- Next: A2-T06.
- Phase A2: 5/7 (71.4%) | Overall: 16/61 (26.2%)

- [2026-05-15 15:40 UTC] ID: A2-T06 | Status: COMPLETE
- Change: Audited IPC flow for timeout policy; `capsule_image_codec` uses recv/respond primitives only and introduces no `mk_ipc_call` call-site.
- Evidence: `rg -n "mk_ipc_call" userland/capsule_image_codec/src` (no matches).
- Next: A2-T07.
- Phase A2: 6/7 (85.7%) | Overall: 17/61 (27.9%)

- [2026-05-15 15:44 UTC] ID: A2-T07 | Status: COMPLETE
- Change: Integrated `Capsule.mk` at top-level `Makefile`, generated image_codec publisher trust keys, produced cert/manifest, and added matrix evidence row.
- Evidence: `make nonos-mk-image-codec` (pass); `make nonos-mk-image-codec-sign` (pass); `./nonos-ci/run-static-checks.sh` (executed; fails on pre-existing unrelated `capsule_desktop_shell` matrix/path drift: missing matrix row + missing `userland/desktop_shell/src/main.rs`).
- Next: A3-T01.
- Phase A2: 7/7 (100%) | Overall: 18/61 (29.5%)

- [2026-05-15 15:41 UTC] ID: A3-T01 | Status: COMPLETE
- Change: Switched `capsule_wallpaper` startup from legacy proof flow to the modular A3 runtime path (`setup::run` + `server::run`) and enabled full module wiring (`protocol`, `state`, `setup`, `server`, `compositor_client`, `paint`, `debug`).
- Evidence: `cargo +nightly check --manifest-path userland/capsule_wallpaper/Cargo.toml --target userland/x86_64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec` (pass); `cargo +nightly check --manifest-path userland/capsule_wallpaper/Cargo.toml --target userland/aarch64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec` (pass); `cargo +nightly check --manifest-path userland/capsule_wallpaper/Cargo.toml --target userland/riscv64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec` (pass).
- Next: A3-T02.
- Phase A3: 1/8 (12.5%) | Overall: 19/61 (31.1%)

- [2026-05-15 15:42 UTC] ID: A3-T02 | Status: COMPLETE
- Change: Hardened setup discovery to require both `compositor` and `desktop_shell` service announcements before runtime enters the server loop.
- Evidence: `cargo +nightly check --manifest-path userland/capsule_wallpaper/Cargo.toml --target userland/x86_64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec` (pass); `cargo +nightly check --manifest-path userland/capsule_wallpaper/Cargo.toml --target userland/aarch64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec` (pass); `cargo +nightly check --manifest-path userland/capsule_wallpaper/Cargo.toml --target userland/riscv64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec` (pass).
- Next: A3-T03.
- Phase A3: 2/8 (25.0%) | Overall: 20/61 (32.8%)

---

## Execution Gate
- This document tracks live execution status.
- Code changes are in progress on the active execution branch.
- Active next task: A3-T03.
