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
- [ ] Add `crate::network::stack::init_network_stack()` call in `microkernel_init`
- [ ] Add `[NET] stack created (early)` boot log marker
- [ ] Compile-check passes

### P2 — Desktop defensive gating
- [ ] Gate `poll_network` + `browser::poll_navigation` on `is_network_available()`
- [ ] One-shot `[DIAG] net_ready` diagnostic on first ready frame
- [ ] Compile-check passes

### P3 — Single xHCI owner
- [ ] Introduce `ENABLE_NET_XHCI` flag in `entry::network`
- [ ] Gate `drivers::xhci::init_xhci()` call behind flag (default off)
- [ ] Emit `[NET] usb_eth=skipped(owner=hid)` when off
- [ ] Compile-check passes

### P4 — Phased cooperative init
- [ ] Input service: phased init (`i2c_hid` → yield → `usb_hid` → yield → endpoint)
- [ ] Input service: per-phase log lines
- [ ] Net service: phased init (`settings` → yield → `manager` → yield → `drivers` → yield → endpoint)
- [ ] Net service: per-phase log lines
- [ ] Endpoint registration moved to after last phase
- [ ] Compile-check passes

### P5 — DHCP backoff
- [ ] Replace `for _ in 0..100_000 { spin_loop() }` with `sleep_us` + `yield_now`
- [ ] Exponential backoff (50ms / 100ms / 200ms cap 1s)
- [ ] Per-attempt log with timestamp
- [ ] Compile-check passes

## 3. Commit checklist (micro-commits)

- [ ] c01: docs(plan): add remediation checklist
- [ ] c02: fix(boot): early network stack init [P1]
- [ ] c03: docs(plan): mark P1 done
- [ ] c04: fix(desktop): readiness-gate network poll [P2]
- [ ] c05: docs(plan): mark P2 done
- [ ] c06: fix(net): gate duplicate xHCI init behind flag [P3]
- [ ] c07: docs(plan): mark P3 done
- [ ] c08: refactor(input): phased init with yields [P4a]
- [ ] c09: refactor(net): phased init with yields [P4b]
- [ ] c10: docs(plan): mark P4 done
- [ ] c11: fix(net): scheduler-friendly DHCP backoff [P5]
- [ ] c12: docs(plan): mark P5 + DoD done

## 4. Validation checklist

- [ ] `cargo fmt` clean
- [ ] `cargo check --lib --features std --target x86_64-apple-darwin` passes
- [ ] Grep: no callers of `drivers::xhci::init_xhci` in `entry::network` reachable when flag off
- [ ] Grep: no `for _ in 0\.\.100_000 \{ core::hint::spin_loop` left in `network/manager`
- [ ] Grep: `init_network_stack` called from `kernel_core/init/entry.rs`

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

- [ ] Compile-clean across all commits
- [ ] No raw spin in DHCP retry path
- [ ] Single xHCI owner reachable
- [ ] Desktop tolerant of unready network
- [ ] Net + input service phases logged and yielding
- [ ] Tracking doc fully checked
