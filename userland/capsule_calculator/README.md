# capsule_calculator

Userland app capsule built on app_skeleton. It routes UI frames through toolkit
IPC and runs a bounded endpoint receive/yield loop.

Verification:
- cargo +nightly check --manifest-path userland/capsule_calculator/Cargo.toml --target userland/{x86_64,aarch64,riscv64}-nonos-user.json -Z build-std=core,alloc -Z json-target-spec
- make nonos-mk-calculator
- make nonos-mk-calculator-sign
