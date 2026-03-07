# NØNOS Kernel — Copilot Instructions

## Identity

Bare-metal x86_64 microkernel. RAM-resident, capability-enforced, cryptographically signed capsule execution. Custom target `x86_64-nonos.json` (PIE, `panic=abort`, red-zone disabled, SSE2 baseline). Toolchain: `nightly-2026-01-16`. License: AGPL-3.0.

## Engineering Mindset

Think like a principal Rust systems engineer building a kernel from first principles. Every line of code runs at ring 0 with no safety net—no OS beneath you, no process isolation protecting you from yourself, no restart-and-retry. This demands a specific mode of reasoning.

## Core Principles

**Correctness over cleverness.** A boring `match` that handles every variant beats a clever bit-trick that's wrong in one edge case. The compiler is your proof assistant—lean on exhaustive matching, type-state patterns, and `#[must_use]` to catch mistakes at compile time rather than at 3am in production.

**Understand before you type.** Read the hardware spec, the existing module's `mod.rs` API surface, and the relevant `abi/*.toml` contract before writing a single line. Ask: *Why does this interface exist? What invariant does it protect?* If you cannot state the invariant, you cannot safely extend the code.

**Make invalid states unrepresentable.** Use Rust's type system to enforce correctness:

```rust
// ❌ BAD — caller can pass any u16
pub fn write_port(port: u16, val: u8) { ... }

// ✅ GOOD — type encodes that the port was validated
pub struct ValidPort(u16);
impl ValidPort {
    pub fn new(port: u16) -> Result<Self, DriverError> {
        if is_allowed_port(port) { Ok(Self(port)) } else { Err(DriverError::InvalidPort) }
    }
}
pub fn write_port(port: ValidPort, val: u8) { ... }
```

**Fail-safe defaults.** When in doubt, deny. Return `Err`, reject the capability request, refuse the MMIO access. A false negative is recoverable; a false positive in a kernel is a security hole.

**No magic numbers.** Every constant has a name, a doc comment explaining its origin (datasheet section, RFC number, hardware register offset), and lives in `types.rs` or a constants block.

## Implementation Workflow

When implementing a new subsystem or feature, follow this sequence:

```
1. CONTRACT   — Define the ABI/interface first (abi/*.toml or mod.rs pub API)
2. TYPES      — Write types.rs: structs, enums, constants, #[repr(C)] for HW
3. ERRORS     — Write error.rs: per-subsystem enum with as_str(), code(), is_recoverable()
4. TESTS      — Write #[cfg(test)] stubs for the API contract (RED phase)
5. IMPLEMENT  — Fill in the logic behind the types (GREEN phase)
6. HARDEN     — Add SAFETY comments, validate MMIO/DMA, rate-limit HW ops
7. INTEGRATE  — Wire into mod.rs re-exports, init_all_drivers(), feature gates
8. VERIFY     — cargo test --features std && make run-serial
```

Never skip step 1. The ABI files in `abi/` are the source of truth—code is an implementation of a contract, not the other way around.

## Design Decision Framework

For every non-trivial choice, reason through:

| Question | Kernel-Specific Concern |
|----------|------------------------|
| What if this panics? | System halts. No recovery. Every path must be `Result`-based. |
| What if this runs in an ISR? | No allocation, no locks, no blocking. Flag-and-defer only. |
| What if an attacker controls the input? | MMIO addresses, DMA buffers, capability tokens, syscall args—all untrusted. Validate before use. |
| What if this races on another core? | SMP is enabled. Every shared mutable state needs `spin::Mutex`, `AtomicBool`, or interrupt-disable. |
| Can I prove this is constant-time? | Any secret-dependent path (crypto keys, capability sigs, nonces) must use `subtle` crate ops. |
| Is this the simplest correct solution? | Kernel code lives forever. Prefer 20 obvious lines over 5 clever ones. |

## Debugging Methodology

No `println!`. No debugger by default. Systematic reasoning is required:

1. **Reproduce** — Write a `#[cfg(test)]` test that triggers the bug on the host, or a QEMU serial-output scenario (`make run-serial`).
2. **Hypothesize** — State a concrete theory: *"The page table entry is not flushed after remap because `invlpg` is missing after the write."*
3. **Instrument** — Add `serial::println()` breadcrumbs at decision points. Use `make debug` (GDB on `:1234`) for memory inspection.
4. **Verify** — Confirm the fix eliminates the symptom *and* the hypothesis explains the root cause.
5. **Regress** — Add a `test_<bug_description>` that would have caught the issue. Leave it in permanently.

Never make random changes hoping something sticks. Every change must follow from a hypothesis.

## Optimization Rules

- **Measure first.** Do not optimize without evidence. Use `make debug` + GDB, serial timing output, or criterion benchmarks on host tests.
- **Algorithmic wins first.** O(n²) → O(n log n) beats any micro-optimization.
- **Reduce allocations.** Use `ArrayVec<T, N>` for bounded collections, `heapless::Vec` for ISR-safe buffers, `SmallVec<[T; N]>` for mostly-small collections. Reserve `alloc::vec::Vec` for genuinely unbounded data.
- **Inline hot paths.** `#[inline]` on functions called in tight loops. `#[inline(always)]` only on port I/O wrappers and functions < 10 instructions.
- **Unsafe as last resort.** If you need `unsafe` for performance, prove the invariant in a `// SAFETY:` comment, benchmark to confirm the gain is real, and wrap it in a safe public API.

## Code Review Self-Check

Before considering any change complete:

- [ ] Does it compile with `cargo clippy` clean?
- [ ] Does `cargo test --features std` pass?
- [ ] Does `make run-serial` boot without new errors?
- [ ] Is every `unsafe` block justified with a `// SAFETY:` comment?
- [ ] Is every error path handled (no `unwrap()`/`expect()`)?
- [ ] Are new features declared in `Cargo.toml` `[features]`?
- [ ] Are new public types re-exported through `mod.rs`?
- [ ] Are hardware-facing structs `#[repr(C)]`?
- [ ] Are secrets zeroed after use?
- [ ] Would a new team member understand this code without asking you?

## Hard Constraints

| Rule | Detail |
|------|--------|
| `#![no_std]` | Never use `std`. Only `core` + `alloc` (via `extern crate alloc`). |
| No external allocator | Global allocator is `linked_list_allocator` behind an `AtomicBool` spinlock. Allocations in ISRs are forbidden. |
| Panic = abort | No unwinding. Every `-> !` divergent path must terminate in `hlt` loop. |
| No floats | Target disables x87/AVX. SSE2-only for SIMD if needed. Do not use `f32`/`f64`. |
| Feature-gated | All optional subsystems behind `nonos-*` Cargo features. Check `Cargo.toml` `[features]` before adding `cfg` guards. Unknown cfgs are deny-linted. |

## Architecture & Memory Model

- **Higher-half kernel:** base `0xFFFF_8000_0000_0000`. Heap minimum 2 MiB.
- **W⊕X enforced:** pages are writable XOR executable, never both. NX stack, SMEP, SMAP, KASLR, CET, PCID all enabled by default features.
- **Page size:** 4 KiB standard, 2 MiB huge pages for kernel text/heap.
- **Linker script** (`linker.ld`): sections are `.text`, `.rodata`, `.data`, `.nonos.manifest`, `.nonos.sig`, `.bss`—in that order. BSS is NOBITS. Stack is 64 KiB after BSS.
- **PIE relocations:** kernel is position-independent; bootloader applies `.rela.dyn` fixups.

## Code Style

### Formatting

```toml
# rustfmt.toml
edition = "2021"
newline_style = "Unix"
use_small_heuristics = "Max"
```

Clippy: `-W clippy::all -W clippy::perf -A clippy::missing_errors_doc`

### Naming

| Element | Convention | Example |
|---------|-----------|---------|
| Functions | `snake_case` | `init_heap()`, `validate_mmio_region()` |
| Types | `PascalCase` | `CapabilityToken`, `DriverError` |
| Constants | `SCREAMING_SNAKE` | `BLOCK_MAGIC`, `KERNEL_PHYS_END` |
| Features | `nonos-` prefix | `nonos-kaslr`, `nonos-syscall-int80` |
| Driver getters | `get_<name>_device()` | `get_ahci_controller()` |
| Driver init | `init_<driver>()` | `init_tpm()` |
| Re-exports | prefix with subsystem | `pub use ahci::get_controller as get_ahci_controller` |

### Derives

- Error enums: `#[derive(Debug, Clone, Copy, PartialEq, Eq)]`
- Capability/ABI types: add `Hash`
- Hardware-crossing structs: `#[repr(C)]` mandatory

### Inline Hints

- `#[inline(always)]` on port I/O wrappers and tight loops
- `#[inline]` on hot-path helpers
- Never `#[inline(always)]` on functions larger than ~10 instructions

## Unsafe Code Policy

- Every `unsafe` block must have a `// SAFETY:` comment explaining the invariant being upheld.
- Wrap raw operations in safe public functions—callers should never see `unsafe`.
- **Port I/O** (`in`/`out`): `pub unsafe fn` with `#[inline(always)]`, `options(nomem, nostack)`.
- **MMIO:** always go through `drivers::security::mmio::validate_mmio_region()` before `read_volatile`/`write_volatile`.
- **DMA:** call `validate_dma_buffer()` (alignment, size, address above `KERNEL_PHYS_END`) before any DMA transfer.
- **`static mut`:** guard with `AtomicBool` spinlocks. Prefer `spin::Mutex` or `spin::RwLock` for new code.
- **Naked functions:** only at entry points (`_start`). Keep to pure `asm!`, call a safe Rust `extern "C" fn` immediately.

## Error Handling

- Per-subsystem error enums—no unified kernel error type.
- Every error enum implements:
  - `as_str(&self) -> &'static str`
  - `impl core::fmt::Display` (delegates to `as_str()`)
  - `code(&self) -> u32` with hex-categorized ranges (e.g., `0x1xxx` MMIO, `0x2xxx` DMA)
  - `is_recoverable(&self) -> bool` and/or `is_security_critical(&self) -> bool`
- Return `Result<T, SubsystemError>` for all fallible operations.
- Boot/init code may log-and-continue for non-critical driver failures, but must propagate critical errors.
- No `unwrap()`/`expect()` in kernel code. Use `match` or `if let`. Panic kills the system.

## Module Structure

```
src/
├── lib.rs              # crate root: #![no_std], alloc_error_handler, flat pub mod list
├── nonos_main.rs       # #![no_main] entry, naked _start, kernel_entry()
├── <subsystem>/
│   ├── mod.rs          # public API surface: submodule decls + pub use re-exports
│   ├── types.rs        # structs, enums, constants
│   ├── error.rs        # SubsystemError enum
│   └── *.rs            # implementation files (private mod unless API)
```

- `mod.rs` is the sole public surface of each subsystem. Re-export everything needed.
- Use `pub(crate)` for cross-module helpers that aren't public API.
- Keep files 50–200 lines. Split when exceeding 300.

## Capability System

The kernel enforces capability-based access control:

- 10 capabilities: `CoreExec`, `IO`, `Network`, `IPC`, `Memory`, `Crypto`, `FileSystem`, `Hardware`, `Debug`, `Admin`
- Stored as `u64` bitmask (each capability is a power-of-2 bit)
- `CapabilityToken`: `owner_module: u64`, `permissions: Vec<Capability>`, `expires_at_ms: Option<u64>`, `nonce: u64`, `signature: [u8; 64]`
- Role presets defined in `capabilities/roles.rs`: `KERNEL`, `SYSTEM_SERVICE`, `USER_APP`, etc.
- Stack: Token → Chain → Delegation → MultiSig → Resource quotas
- All capability checks must be constant-time (via `subtle` crate)
- New syscalls must declare required caps in `abi/syscalls.toml`

## Cryptography

- Internal implementations preferred for Ed25519, Curve25519, SHA-3, BLAKE3, SHA-2.
- Post-quantum: ML-KEM (Kyber) via PQClean C (compiled in `build.rs`), ML-DSA (Dilithium) feature-gated.
- ZK proofs: Groth16 (arkworks) and Halo2 (KZG) for boot attestation.
- **Constant-time:** all secret-dependent operations must use `subtle::ConstantTimeEq` / `subtle::ConditionallySelectable`. No branching on secrets.
- **Zeroization:** secrets must be zeroed after use (`core::ptr::write_volatile` + compiler fence).
- Never implement custom crypto primitives—wrap audited implementations.
- SHA-1 exists only for legacy protocol compat (Git/TAP/TOTP) behind `sha1-legacy` feature.

## Concurrency

- **Spinlocks only:** `spin::Mutex`, `spin::RwLock`, `spin::Lazy`. No sleeping locks (no scheduler guarantee in early boot).
- **Atomics:** `Relaxed` for flags/counters, `Acquire`/`Release` for spinlock state, `SeqCst` for init-once semantics.
- **Interrupt safety:** disable interrupts (`x86_64::instructions::interrupts::without_interrupts`) before acquiring locks that ISRs might contend. ISRs must never allocate or acquire non-ISR locks.
- **SMP:** per-CPU data via APIC ID indexing. No `static mut` shared across cores without atomic protection.

## Interrupt Handling

- ISRs in `interrupts/` module. Registered via IDT in `sys::idt`.
- ISR body must be minimal: acknowledge interrupt, set a flag or enqueue work, return. No allocation, no lock acquisition, no I/O beyond the acknowledging port write.
- Deferred work runs in the main loop or a softirq-like mechanism.
- Use `#[naked]` only for the raw ISR stub; call a safe handler function immediately.

## Driver Development

Place new drivers in `src/drivers/<name>/` with `mod.rs`, `types.rs`, `error.rs`.

Register in `src/drivers/mod.rs`: add `pub mod`, re-exports, and call `init_<name>()` from `init_all_drivers()`.

Every driver must:

- Define `<Name>Error` enum with `as_str()`, `code()`, `is_recoverable()`
- Define `<Name>Stats` struct for telemetry
- Validate all MMIO/DMA/PCI access through `drivers::security::*`
- Implement `RateLimiter` for operations that touch hardware
- Register with `CriticalDriver` if it's security-relevant (`DriverType` + `SecurityLevel`)

Driver security validation layer (`drivers/security/`): `mmio.rs`, `dma.rs`, `pci.rs`, `lba.rs`, `rate_limiter.rs`.

## ABI Contract

Machine-readable specs live in `abi/`:

| File | Defines |
|------|---------|
| `syscalls.toml` | Syscall numbers, arg types, required capabilities, error codes |
| `caps.toml` | Capability bits, groups, token format, MAC algorithm |
| `wire.toml` | Register conventions, endianness, alignment |
| `vm.toml` | Page sizes, memory protections, ASLR config, heap policy |
| `manifest.toml` | Capsule ELF format, signature scheme, measurement context |

When adding a syscall: update `abi/syscalls.toml` first, then implement. The ABI files are the source of truth.

## Build System

```bash
make              # build bootloader + kernel + ESP
make run          # boot in QEMU (UEFI, q35, e1000)
make run-serial   # headless serial-only boot
make debug        # QEMU with GDB stub on :1234
make test         # cargo test --features std
make check        # clippy (kernel + bootloader)
make fmt          # rustfmt
make iso          # create bootable ISO
```

Kernel builds with: `cargo build --release --target x86_64-nonos.json -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem`

`build.rs` compiles PQClean C, generates manifest, signs kernel with Ed25519, embeds build metadata.

Signing key: `NONOS_SIGNING_KEY` env var or `.keys/dev-signing.seed` (32-byte Ed25519 seed).

macOS requires explicit SDK paths for cross-compilation (handled in Makefile).

Tests run on host with `--features std` (enables `rand` and standard test harness).

## Testing

### Unit tests (`#[cfg(test)]`)

- Colocated in source or sibling `tests.rs` files
- Run on host: `cargo test --features std`
- Test naming: `test_<thing>` (e.g., `test_validate_mmio_region`)
- Standard assertions: `assert!()`, `assert_eq!()`, `.is_ok()`, `.is_err()`
- No custom test harness or assertion macros

### Runtime selftests

- `kernel_selftest::run() -> bool` called during boot
- Exercises hardware and crypto in the real execution environment
- Output via `serial::println()` and `console::write_message()`

### QEMU validation

- Test all changes with `make run` before committing
- Serial output (`make run-serial`) for headless CI verification
- GDB attach (`make debug`) for runtime debugging

## File Headers

Every `.rs` file starts with:

```rust
// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// ... AGPL-3.0 license block ...
```

## Kernel Design Patterns

### Type-State for Hardware Lifecycle

Encode hardware initialization stages in the type system so mis-ordered operations are compile errors:

```rust
pub struct Uninitialized;
pub struct Ready;

pub struct Device<State> {
    base: usize,
    _state: core::marker::PhantomData<State>,
}

impl Device<Uninitialized> {
    pub fn probe(base: usize) -> Result<Self, DriverError> { /* ... */ }
    pub fn init(self) -> Result<Device<Ready>, DriverError> { /* ... */ }
}

impl Device<Ready> {
    pub fn read_register(&self, offset: u16) -> u32 { /* ... */ }
}
// Device<Uninitialized> has no read_register — misuse is impossible.
```

### Newtype Validation for Hardware Addresses

Never pass raw `u64` for addresses, ports, or sizes across API boundaries:

```rust
pub struct PhysAddr(u64);
impl PhysAddr {
    pub fn new(addr: u64) -> Result<Self, MemError> {
        if addr == 0 { return Err(MemError::NullAddress); }
        if addr % 4096 != 0 { return Err(MemError::Unaligned); }
        Ok(Self(addr))
    }
    pub fn as_u64(&self) -> u64 { self.0 }
}
```

### ISR-Safe Deferred Work

ISRs set a flag; the main loop or softirq drains it:

```rust
static PENDING_WORK: AtomicU64 = AtomicU64::new(0);
const WORK_KEYBOARD: u64 = 1 << 0;
const WORK_NETWORK:  u64 = 1 << 1;

// In ISR — no allocation, no locks:
fn keyboard_isr() {
    acknowledge_interrupt();
    PENDING_WORK.fetch_or(WORK_KEYBOARD, Ordering::Release);
}

// In main loop — safe to allocate and lock:
fn drain_pending_work() {
    let bits = PENDING_WORK.swap(0, Ordering::Acquire);
    if bits & WORK_KEYBOARD != 0 { handle_keyboard_input(); }
    if bits & WORK_NETWORK  != 0 { handle_network_rx(); }
}
```

### Init-Once with Atomic Guard

For subsystems that initialize exactly once during boot:

```rust
static INIT_DONE: AtomicBool = AtomicBool::new(false);

pub fn init_subsystem() -> Result<(), SubsystemError> {
    if INIT_DONE.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return Ok(()); // Already initialized — idempotent
    }
    // ... one-time setup ...
    Ok(())
}
```

### Validate-Then-Act for Hardware Access

Every hardware interaction follows: validate → disable interrupts (if contended) → act → re-enable:

```rust
pub fn read_device_register(addr: PhysAddr, offset: u16) -> Result<u32, DriverError> {
    validate_mmio_region(addr.as_u64(), 4)?;
    let val = x86_64::instructions::interrupts::without_interrupts(|| {
        // SAFETY: address validated by validate_mmio_region above
        unsafe { core::ptr::read_volatile((addr.as_u64() + offset as u64) as *const u32) }
    });
    Ok(val)
}
```

## What NOT to Do

- Do not add `std` dependencies to the kernel crate (only to `[dev-dependencies]` behind `--features std`)
- Do not use `println!`—use `serial::println(b"...")` or `console::write_message("...")`
- Do not add `unwrap()` or `expect()` in kernel paths
- Do not allocate in interrupt handlers
- Do not create `static mut` without atomic guards
- Do not branch on secret data without constant-time primitives
- Do not add new features without declaring them in `Cargo.toml` `[features]` (denied by `unexpected_cfgs`)
- Do not modify the linker script section order without understanding the bootloader's relocation logic
- Do not use `f32`/`f64` (no x87/AVX on target)
