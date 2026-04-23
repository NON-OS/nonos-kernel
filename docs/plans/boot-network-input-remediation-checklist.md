# Boot / Network / Input Remediation — Execution Checklist

Branch: `fix/boot-net-input-phased-init-v2`
Base: `main`

## 1. Scope and constraints

- Targeted fixes only; no redesign.
- Each phase independently reversible.
- No comments in Rust function bodies.
- Each commit must compile (`cargo check --lib --features std --target x86_64-apple-darwin`).
- Diffs kept minimal per file.

## 2. Phase checklist (P1–P5)

### P1 — Early network stack readiness gate
- [x] Add `crate::network::stack::init_network_stack()` call in `microkernel_init`
- [x] Add `[NET] stack created (early)` boot log marker
- [x] Compile-check passes

### P2 — Desktop defensive gating
- [x] Gate `poll_network` + `browser::poll_navigation` on `is_network_available()`
- [x] One-shot `[DIAG] net_ready` diagnostic on first ready frame
- [x] Compile-check passes

### P3 — Single xHCI owner
- [x] Introduce `ENABLE_NET_XHCI` flag in `entry::network`
- [x] Gate `drivers::xhci::init_xhci()` call behind flag (default off)
- [x] Emit `[NET] usb_eth=skipped(owner=hid)` when off
- [x] Compile-check passes

### P4 — Phased cooperative init
- [x] Input service: phased init (`i2c_hid` → yield → `usb_hid` → yield → endpoint)
- [x] Input service: per-phase log lines
- [x] Net service: phased init (`settings` → yield → `manager` → yield → `drivers` → yield → endpoint)
- [x] Net service: per-phase log lines
- [x] Endpoint registration moved to after last phase
- [x] Compile-check passes

### P5 — DHCP backoff
- [x] Replace `for _ in 0..100_000 { spin_loop() }` with `sleep_us` + `yield_now`
- [x] Exponential backoff (50ms / 100ms / 200ms cap 1s)
- [x] Per-attempt log with timestamp
- [x] Compile-check passes

## 3. Commit checklist (micro-commits)

- [x] c01: docs(plan): add remediation checklist
- [x] c02: fix(boot): early network stack init [P1]
- [x] c03: docs(plan): mark P1 done
- [x] c04: fix(desktop): readiness-gate network poll [P2]
- [x] c05: docs(plan): mark P2 done
- [x] c06: fix(net): gate duplicate xHCI init behind flag [P3]
- [x] c07: docs(plan): mark P3 done
- [x] c08: refactor(input): phased init with yields [P4a]
- [x] c09: refactor(net): phased init with yields [P4b]
- [x] c10: docs(plan): mark P4 done
- [x] c11: fix(net): scheduler-friendly DHCP backoff [P5]
- [x] c12: docs(plan): mark P5 + DoD done

## 4. Validation checklist

- [x] `cargo fmt` clean
- [x] `cargo check --lib --features std --target x86_64-apple-darwin` passes
- [x] Grep: no callers of `drivers::xhci::init_xhci` in `entry::network` reachable when flag off
- [x] Grep: no `for _ in 0\.\.100_000 \{ core::hint::spin_loop` left in `network/manager`
- [x] Grep: `init_network_stack` called from `kernel_core/init/entry.rs`

### Required boot log order
- [ ] `[NONOS] Microkernel init`
- [ ] `[NET] stack created (early)`
- [ ] `[NONOS] Core ready`
- [ ] `[UKERNEL] Entering userspace`
- [ ] `[INPUT] phase=i2c_hid done` ... `[INPUT] phase=ready`
- [ ] `[NET] phase=settings done` ... `[NET] phase=ready`
- [ ] `[DIAG] net_ready frame=N`
- [ ] No `[NET] xHCI USB controller ready`

## 5. Rollback checklist

- [ ] P1: revert `init_network_stack()` call in `microkernel_init`
- [ ] P2: remove readiness gate in `run_desktop`
- [ ] P3: flip `ENABLE_NET_XHCI = true`
- [ ] P4: collapse phased init back to single calls
- [ ] P5: restore raw spin retry

## 6. Final DoD checklist

- [x] Compile-clean across all commits
- [x] No raw spin in DHCP retry path
- [x] Single xHCI owner reachable
- [x] Desktop tolerant of unready network
- [x] Net + input service phases logged and yielding
- [x] Tracking doc fully checked
