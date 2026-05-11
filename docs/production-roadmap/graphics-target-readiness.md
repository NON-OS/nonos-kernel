# Graphics Target Readiness

Date: 2026-05-11
Scope: graphics syscall contract and userland graphics path readiness by target

## x86_64-nonos
status: partial
verification: ./nonos-ci/run-static-checks.sh => PASS
verification: RUSTUP_TOOLCHAIN=nightly-2026-01-16 cargo check -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem --target x86_64-nonos.json --features "nonos-capsule-wallpaper nonos-wallpaper-smoketest" => success (warnings only)
verification: make nonos-mk-wallpaper-test => success (warnings only)
verification: make nonos-mk-run-serial => blocked by [NONOS] Handoff FAIL; wallpaper PASS marker sequence not observed
notes: build-level readiness is proven; runtime marker closure remains blocked by handoff failure.

## aarch64-nonos
status: not-validated
verification: no passing aarch64 graphics build/runtime evidence captured on this branch as of 2026-05-11
notes: architecture support remains open; do not claim readiness until static checks and target-specific build/run evidence are recorded.
