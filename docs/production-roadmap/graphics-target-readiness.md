# Graphics Target Readiness

Date: 2026-05-11
Scope: graphics syscall contract and userland graphics path readiness by target

## x86_64-nonos
status: partial
verification: ./nonos-ci/run-static-checks.sh => PASS
verification: RUSTUP_TOOLCHAIN=nightly-2026-01-16 cargo check -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem --target x86_64-nonos.json --features "nonos-capsule-wallpaper nonos-wallpaper-smoketest" => success (warnings only)
verification: make nonos-mk-wallpaper-test => success (warnings only)
verification: make nonos-mk-run-serial => no `[NONOS] Handoff FAIL` marker observed; runtime currently stalls after boot handoff markers at `R` before `[NONOS] Handoff OK` / wallpaper markers
verification: make nonos-mk-run-serial | tee /tmp/graphics_runtime_fresh.log + marker grep => observed `[CR3OK]` and `R`; no `[NONOS] Handoff OK` / `[NONOS] Handoff FAIL` / `[wallpaper]` success markers
verification: make nonos-mk-run-serial | tee /tmp/graphics_runtime_trace.log => run blocked by host forwarding conflict (`Could not set up host forwarding rule 'tcp::8080-:80'`), no additional kernel-runtime marker evidence captured
notes: build-level readiness is proven; runtime marker closure remains blocked by a post-handoff-transfer stall that still prevents wallpaper PASS sequence capture.

## aarch64-nonos
status: not-validated
verification: no passing aarch64 graphics build/runtime evidence captured on this branch as of 2026-05-11
notes: architecture support remains open; do not claim readiness until static checks and target-specific build/run evidence are recorded.
