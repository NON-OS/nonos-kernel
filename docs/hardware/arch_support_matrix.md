# NØNOS architecture support matrix

Status values:

- `production`: builds, boots on QEMU, boots on at least one real machine, passes the platform smoke markers in `tests/boot/`.
- `qemu`: builds, boots on QEMU, no real-machine proof yet.
- `compiles`: source builds for the target via `cargo check`; no boot run yet.
- `designed`: trait surface and module skeleton present, no source.
- `missing`: not in scope yet.

A platform is `production` only when both QEMU smoke and real-machine proof exist on the active build.

## Per-arch state

| Arch | Triple | Status | Boot | Memory map | Paging | Interrupt controller | Timer | PCI | Serial | Smoke marker |
|---|---|---|---|---|---|---|---|---|---|---|
| x86_64 | `x86_64-nonos` | qemu (real-hardware partial) | UEFI OVMF | E820/EFI memmap | 4-level | local APIC + IO-APIC | TSC + APIC timer | yes | 16550 PIO | `tests/boot/keyring_round_trip.sh` and others |
| aarch64 | `aarch64-nonos` | compiles | DTB | DTB-derived | TTBR0/TTBR1 | GIC | generic timer | ECAM | PL011 | not yet |
| riscv64 | `riscv64-nonos` | compiles | DTB | DTB-derived | Sv39/Sv48 | PLIC + CLINT | mtime | ECAM | NS16550 | not yet |

Marking aarch64 or riscv64 as `qemu` requires a corresponding `tests/boot/<arch>_*.sh` script that emits at minimum:

```
[ARCH] boot ok
[MEM] map ok
[IRQ] timer ok
[IPC] ok
[CAPSULE] init ok
[DRIVER] device list ok
```

Without that file, the static gate refuses to call the platform supported.

## Boot platforms tracked

| Platform | Arch | Boot method | Status | Smoke file |
|---|---|---|---|---|
| QEMU x86_64 OVMF | x86_64 | UEFI | qemu | `tests/boot/keyring_round_trip.sh` (partial coverage) |
| QEMU x86_64 BIOS | x86_64 | legacy BIOS | excluded | n/a (UEFI-only target) |
| QEMU aarch64 virt | aarch64 | DTB + UEFI | missing | `tests/boot/aarch64_virt.sh` (planned) |
| QEMU riscv64 virt | riscv64 | DTB + OpenSBI | missing | `tests/boot/riscv64_virt.sh` (planned) |
| Real x86_64 Intel laptop | x86_64 | UEFI | partial | `docs/hardware/lab/<machine>.md` (planned) |
| Real x86_64 AMD laptop | x86_64 | UEFI | missing | n/a |
| Real x86_64 mini PC | x86_64 | UEFI | missing | n/a |
| Real x86_64 server | x86_64 | UEFI | missing | n/a |
| Raspberry Pi 4/5 | aarch64 | UEFI or U-Boot + DTB | missing | n/a |
| RISC-V dev board | riscv64 | OpenSBI + DTB | missing | n/a |

## Per-arch primitive checklist

Each item is one of: `done`, `wip`, `missing`, `n/a`.

| Primitive | x86_64 | aarch64 | riscv64 |
|---|---|---|---|
| boot entry | done | wip | wip |
| memory map | done | wip | wip |
| paging | done | wip | wip |
| heap | done | wip | wip |
| interrupt controller | done | wip | wip |
| timer | done | wip | wip |
| serial console | done | wip | wip |
| PCI / ECAM | done | missing | missing |
| ACPI tables | done | missing | n/a |
| DTB walker | n/a | missing | missing |
| IOMMU | designed | missing | missing |
| MMU TLB flush | done | wip | wip |
| context switch | done | wip | wip |
| syscall entry | done | missing | missing |
| user-mode return | done | missing | missing |

`wip` means the source compiles but no boot smoke exists.

## Multi-arch ABI

| Surface | Notes |
|---|---|
| `BootHandoffV1` | arch-agnostic for the kernel; per-arch bootloader fills in the arch-specific portion |
| Capsule manifest | arch-agnostic |
| Capsule package format | per-arch artifact list (`x86_64-nonos`, `aarch64-nonos`, `riscv64-nonos`); installer picks one |
| Syscall numbers | arch-agnostic; same `SyscallNumber` enum on every arch |
| `DeviceRecord` (broker) | arch-agnostic, big-endian fields |
| `InputEvent` | arch-agnostic |
| `LocalReceipt` (NOX) | arch-agnostic |

## Out of scope

- 32-bit targets (i686, armv7). NØNOS is 64-bit only.
- Big-endian targets. The capsule wire format is big-endian on the wire, but the kernel runs little-endian on every supported arch.
- POWER / s390x. No plan.
