# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NONOS is a zero-state capability-based security microkernel written entirely in Rust (nightly). It implements cryptographic integrity validation (Ed25519 signatures, Groth16 ZK proofs, BLAKE3 hashing) and a capability-based security model replacing traditional root/privilege escalation.

- **Language:** 100% Rust, `#![no_std]`, nightly-2026-01-16 (pinned due to LLVM regressions)
- **Target:** `x86_64-unknown-none-elf` (bare metal), custom target spec in `x86_64-nonos.json`
- **License:** AGPL-3.0
- **Version:** 0.8.3 (Alpha)

## Build Commands

```bash
make              # Full build: PQC libs -> bootloader -> kernel -> sign -> ZK proofs -> ISO
make run          # Boot in QEMU with graphics (Ctrl+A X to quit)
make run-serial   # Boot in QEMU headless (serial only)
make debug        # QEMU with GDB server on localhost:1234
make iso          # Create bootable ISO
make test         # Run kernel test suite (host + bootloader)
make clean        # Remove all build artifacts
make fmt          # cargo fmt (kernel + bootloader)
make check        # cargo clippy (kernel + bootloader)
```

### Running Tests

Tests run on the host, not bare metal. The `std` feature enables `rand` and the standard test harness:

```bash
# Full test suite
make test

# Single test or module
cargo test --lib --features std --target <host-target> <test_name>
# e.g.: cargo test --lib --features std --target aarch64-apple-darwin test_validate_mmio_region

# Kernel-only build (no full pipeline)
cargo build --release --target x86_64-nonos.json -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem

# Minimal kernel (no default features, ~200KB)
cargo build --release --no-default-features --features "kernel,standalone"
```

Host target is `aarch64-apple-darwin` on Apple Silicon, `x86_64-apple-darwin` on Intel Mac, `x86_64-unknown-linux-gnu` on Linux.

macOS requires explicit SDK paths for cross-compilation (handled automatically by the Makefile).

## Architecture

### Kernel Entry Flow

`_start` (naked asm in `src/nonos_main.rs`) -> `kernel_entry` -> `init_core_systems()` -> `init_handoff()` -> `boot_microkernel()` -> `microkernel_init()` -> `microkernel_main()`.

### Boot Chain (10 stages)

UEFI init -> config -> Secure Boot/TPM -> hardware enumeration -> load kernel -> BLAKE3 hash -> Ed25519 verify -> Groth16 ZK verify -> ELF parse -> handoff to kernel. Bootloader lives in `nonos-bootloader/`.

### Module Structure

```
src/
  lib.rs              # crate root: #![no_std], alloc_error_handler, flat pub mod list
  nonos_main.rs       # #![no_main] entry, naked _start, kernel_entry()
  <subsystem>/
    mod.rs            # public API surface: submodule decls + pub use re-exports
    types.rs          # structs, enums, constants
    error.rs          # SubsystemError enum
    *.rs              # implementation files
```

`mod.rs` is the sole public surface of each subsystem. Use `pub(crate)` for cross-module helpers.

### Major Subsystems

- **kernel_core/** -- Microkernel init, process isolation, service spawning
- **capabilities/** -- Capability tokens (32-byte ID, 64-bit rights bitmap, SHA3-256 MAC). ABI in `abi/caps.toml`
- **process/** -- PCBs, fork/exec, signals, namespaces, cgroups
- **sched/** -- CFS-like scheduler, runqueues, context switching
- **memory/** -- Buddy allocator, paging, TME/SME encryption, NUMA, slab
- **syscall/** -- INT 0x80 and SYSCALL/SYSRET, io_uring, epoll, VDSO
- **fs/** -- VFS layer + ~23 filesystem implementations (ext4, FAT32, Btrfs, CryptoFS, FUSE, NFS, etc.)
- **network/** -- Full TCP/IP stack + privacy layers (Tor, NYM, Dandelion++, I2P, QUIC, TLS, WireGuard)
- **drivers/** -- Storage (AHCI, NVMe, Virtio), network (e1000, mlx5), USB (XHCI, EHCI), display, audio, IOMMU
- **crypto/** -- AES, ChaCha20, Ed25519, ML-KEM-768, ML-DSA-3, SLH-DSA, BLAKE3, SHA3, ZK proofs
- **npkg/** -- NONOS capsule package format (signed ELF with manifest)
- **zk_engine/** and **nox/** -- Zero-knowledge proof execution and privacy/anonymity engine

### ABI Contract Files (`abi/`)

Machine-readable specs that are the source of truth -- code implements these contracts:

| File | Defines |
|------|---------|
| `syscalls.toml` | Syscall numbers, arg types, required capabilities, error codes |
| `caps.toml` | Capability bits, groups, token format, MAC algorithm |
| `wire.toml` | Register conventions, endianness, alignment |
| `vm.toml` | Page sizes, memory protections, ASLR config, heap policy |
| `manifest.toml` | Capsule ELF format, signature scheme, measurement context |

When adding a syscall: update `abi/syscalls.toml` first, then implement.

### Capability Model

11 core capabilities (CoreExec, IO, Network, IPC, Memory, Crypto, FileSystem, Hardware, Debug, Admin, RegisterService). Tokens stored as `u64` bitmask. Delegation follows strict subset rules (OPER -> SERVICE -> BASIC). All capability checks must be constant-time (via `subtle` crate).

### Memory Model

- Higher-half kernel: base `0xFFFF_8000_0000_0000`, heap minimum 2 MiB
- W^X enforced: pages are writable XOR executable, never both
- 4 KiB standard pages, 2 MiB huge pages for kernel text/heap
- PIE: kernel is position-independent; bootloader applies `.rela.dyn` fixups
- Linker script (`linker.ld`): `.text`, `.rodata`, `.data`, `.nonos.manifest`, `.nonos.sig`, `.bss`. Stack is 64 KiB after BSS

### Key Files

- `Makefile` -- Master build orchestration (10-stage pipeline)
- `Cargo.toml` -- 52+ modules, extensive feature flags for conditional compilation
- `build.rs` -- Compiles PQClean C, generates manifest, signs kernel, embeds build metadata
- `x86_64-nonos.json` -- Custom LLVM bare-metal target
- `linker.ld` -- PIE linker script with page-aligned sections
- `nonos-bootloader/keys/signing_key_v1.bin` -- Ed25519 signing key (32 bytes)

## Implementation Workflow

When implementing a new subsystem or feature:

1. **CONTRACT** -- Define the ABI/interface first (`abi/*.toml` or `mod.rs` pub API)
2. **TYPES** -- Write `types.rs`: structs, enums, constants, `#[repr(C)]` for HW
3. **ERRORS** -- Write `error.rs`: per-subsystem enum with `as_str()`, `code()`, `is_recoverable()`
4. **TESTS** -- Write `#[cfg(test)]` stubs for the API contract
5. **IMPLEMENT** -- Fill in the logic
6. **HARDEN** -- Add SAFETY comments, validate MMIO/DMA, rate-limit HW ops
7. **INTEGRATE** -- Wire into `mod.rs` re-exports, `init_all_drivers()`, feature gates
8. **VERIFY** -- `cargo test --features std && make run-serial`

## Hard Constraints

| Rule | Detail |
|------|--------|
| `#![no_std]` | Never use `std`. Only `core` + `alloc` (via `extern crate alloc`). `std` only in `[dev-dependencies]` behind `--features std`. |
| No floats | Target disables x87/AVX. SSE2-only for SIMD. Do not use `f32`/`f64`. |
| Panic = abort | No unwinding. Every `-> !` divergent path must terminate in `hlt` loop. |
| No `unwrap()`/`expect()` | Use `match` or `if let`. Panic kills the system. |
| No allocation in ISRs | ISR body: acknowledge interrupt, set a flag or enqueue work, return. |
| Feature-gated | All optional subsystems behind `nonos-*` Cargo features. Unknown cfgs are deny-linted. |
| No `println!` | Use `serial::println(b"...")` or `console::write_message("...")` |
| Constant-time crypto | All secret-dependent operations use `subtle::ConstantTimeEq` / `ConditionallySelectable`. No branching on secrets. |

## Code Conventions

### Error Handling

Per-subsystem error enums (no unified kernel error type). Every error enum implements:
- `as_str(&self) -> &'static str`
- `impl core::fmt::Display` (delegates to `as_str()`)
- `code(&self) -> u32` with hex-categorized ranges (e.g., `0x1xxx` MMIO, `0x2xxx` DMA)
- `is_recoverable(&self) -> bool` and/or `is_security_critical(&self) -> bool`

Derives: `#[derive(Debug, Clone, Copy, PartialEq, Eq)]`. Add `Hash` for capability/ABI types. Hardware-crossing structs: `#[repr(C)]` mandatory.

### Naming

| Element | Convention | Example |
|---------|-----------|---------|
| Functions | `snake_case` | `init_heap()`, `validate_mmio_region()` |
| Types | `PascalCase` | `CapabilityToken`, `DriverError` |
| Constants | `SCREAMING_SNAKE` | `BLOCK_MAGIC`, `KERNEL_PHYS_END` |
| Features | `nonos-` prefix | `nonos-kaslr`, `nonos-syscall-int80` |
| Driver init | `init_<driver>()` | `init_tpm()` |

### Unsafe Code

- Every `unsafe` block must have a `// SAFETY:` comment explaining the invariant
- Wrap raw operations in safe public functions -- callers should never see `unsafe`
- Port I/O: `pub unsafe fn` with `#[inline(always)]`, `options(nomem, nostack)`
- MMIO: always go through `drivers::security::mmio::validate_mmio_region()` before `read_volatile`/`write_volatile`
- DMA: call `validate_dma_buffer()` before any DMA transfer
- `static mut`: guard with `AtomicBool` spinlocks. Prefer `spin::Mutex` or `spin::RwLock` for new code

### Concurrency

- Spinlocks only: `spin::Mutex`, `spin::RwLock`, `spin::Lazy`. No sleeping locks.
- Atomics: `Relaxed` for flags/counters, `Acquire`/`Release` for spinlock state, `SeqCst` for init-once semantics.
- Interrupt safety: disable interrupts (`x86_64::instructions::interrupts::without_interrupts`) before acquiring locks that ISRs might contend.
- SMP: per-CPU data via APIC ID indexing. No `static mut` shared across cores without atomic protection.

### Secrets

- Zeroed after use (`core::ptr::write_volatile` + compiler fence)
- Never implement custom crypto primitives -- wrap audited implementations
- Post-quantum: ML-KEM via PQClean C (compiled in `build.rs`), ML-DSA feature-gated

## Driver Development

Place new drivers in `src/drivers/<name>/` with `mod.rs`, `types.rs`, `error.rs`. Register in `src/drivers/mod.rs`: add `pub mod`, re-exports, and call `init_<name>()` from `init_all_drivers()`.

Every driver must:
- Define `<Name>Error` enum with `as_str()`, `code()`, `is_recoverable()`
- Define `<Name>Stats` struct for telemetry
- Validate all MMIO/DMA/PCI access through `drivers::security::*`
- Implement `RateLimiter` for hardware operations
- Register with `CriticalDriver` if security-relevant

Driver security validation layer: `drivers/security/` (`mmio.rs`, `dma.rs`, `pci.rs`, `lba.rs`, `rate_limiter.rs`).

## File Headers

Every `.rs` file starts with the AGPL-3.0 license block:
```rust
// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// ... AGPL-3.0 license block ...
```
