# Arch boundary audit (H1)

The kernel is supposed to keep arch-specific code under `src/arch/`
and reach it through a thin trait that every other module calls.
Today that trait does not exist, and arch-specific bits leak into
many subsystems. This document inventories the leaks so the H1
slice can fix them in priority order.

## 1. Quantified leak surface

Counted on the active build, excluding `src/arch/`:

| Pattern | Count | Notes |
|---|---|---|
| `crate::arch::x86_64::` | 70 | direct path imports |
| `asm!` and `naked_asm!` | 210 | inline asm outside `src/arch` |
| `cfg(target_arch = ...)` | 82 | per-arch conditionals outside `src/arch` |

The `asm!` count is the largest tax. Most of it is benign (memory
fences, LFENCE / SFENCE, RDTSC, CPUID), but every site that uses an
x86 mnemonic blocks aarch64/riscv64 unless wrapped in a `cfg`.

## 2. Per-subsystem hot spots

| Subsystem | Sites | Leak shape |
|---|---|---|
| `src/memory/iommu` | 6 imports | Intel VT-d / AMD-Vi register access |
| `src/usercopy/copy` | 5 imports | per-CPU fault recovery slot |
| `src/log/backend/vga` | 5 imports | CGA text-mode backend |
| `src/security/hardening` | 7 asm | spectre / retpoline mitigations |
| `src/crypto/util` | 7 asm | RDRAND, RDTSC entropy |
| `src/process/address_space` | 5 asm | CR3 reload, INVLPG |
| `src/process/userspace` | 4 asm | iretq, swapgs, syscall return |
| `src/memory/paging` | 4 asm | CR2 read on page fault, INVLPG |
| `src/memory/mmu` | 3 asm | CR3 read |
| `src/interrupts/handlers` | 4 asm | IRQ ack on local APIC |
| `src/syscall/tls` | 2 asm | GS / FS swap |
| `src/smp/*` | 8 imports | per-CPU, IPI |
| `src/nonos_time/high_precision` | 3 imports | TSC frequency calibration |
| `src/log/manager/state` | 2 imports | CGA backend dispatch |

## 3. Classification

Each leak is one of:

- `arch_trait`: belongs behind a typed `Arch::*` method.
- `arch_module`: belongs under `src/arch/<arch>/<subsystem>/` and called via a thin shim.
- `legitimate_cfg`: a per-arch implementation of a primitive that is itself per-arch (e.g. CR3 vs. TTBR0 in the paging manager).
- `legacy`: dead post-demolition code path that should be removed.

H1 work order, by classification:

| Classification | Action |
|---|---|
| `arch_trait` | implement the trait method, replace call site with the trait call |
| `arch_module` | move the body under `src/arch/<arch>/`, expose the same name from a per-arch facade |
| `legitimate_cfg` | leave as is, ensure each arch has its own arm |
| `legacy` | delete |

## 4. Priority order for H1

1. `Arch::halt` and `Arch::halt_loop`. Every panic path uses them; all three arches need them.
2. `Arch::enable_interrupts` / `Arch::disable_interrupts` / `Arch::interrupts_enabled`. Used by every locking primitive that masks IRQs.
3. `Arch::current_cpu_id`. Per-CPU subsystems read this on every dispatch.
4. `Arch::read_time_counter`. `nonos_time::high_precision` is the worst offender; one trait call replaces the cfg ladder.
5. `Arch::flush_tlb` / `Arch::flush_tlb_one(addr)`. `memory::paging` and `process::address_space` both reach in.
6. `Arch::switch_address_space(root_phys)`. CR3 / TTBR0 / SATP write.
7. `Arch::set_kernel_stack(va)` and `Arch::program_per_cpu_base(va)`. Trap entry needs both.
8. `Arch::irq_ack(vector)` and `Arch::irq_bind(vector, handler)`. Broker `MkIrqBind` calls these.

Items 1-4 are leaf calls. Items 5-8 mutate per-CPU state and need careful ownership. The H1 slice ships 1-4 in one commit and 5-8 in a second.

## 5. Files to be touched in priority slice (1-4)

```
src/arch/mod.rs                       new trait declarations
src/arch/x86_64/<various>             implement trait for x86_64
src/process/userspace/asm.rs          replace direct halt
src/sched/scheduler/idle.rs           replace direct halt
src/interrupts/safety/<files>         replace direct enable/disable
src/smp/cpu.rs                        replace direct current_cpu_id
src/nonos_time/high_precision.rs      replace direct RDTSC ladder
src/security/hardening/<files>        evaluate per-site (some are legit_cfg)
```

aarch64/riscv64: do not implement the trait body in this slice. The
trait declaration exists, the per-arch impl block is empty (no
`Arch` impl present), and a build for those arches fails with
"Arch not implemented" until the body is real. That is honest:
the arch is `compiles` not `qemu` until the body lands.

## 6. What this audit does not do

- it does not move every `asm!` site behind a trait. Many are local
  primitives (LFENCE for entropy timing) that belong where they are.
- it does not delete `legacy` leaks. Each one needs a per-file
  decision; that lands in subsequent slices.
- it does not promise multi-arch runtime today. The point of the
  audit is to enumerate what a real aarch64 / riscv64 boot needs;
  shipping that is H4.

## 7. Exit criteria

H1 closes when:

1. `Arch` trait declared in `src/arch/mod.rs` with the eight
   primitives above.
2. x86_64 backend implements every method without `unimplemented!`.
3. The 4 leaf-call call sites (halt, irq enable/disable, cpu_id,
   read_time_counter) route through the trait.
4. `bash tools/ci/run-static-checks.sh` adds a baseline for "arch
   leaks outside src/arch" and the count does not grow.
5. `make nonos-mk-check` green.

Multi-arch runtime is H4 (QEMU smoke per arch) and H5 (real
hardware). H1 is the boundary, not the bring-up.
