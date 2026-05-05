# NØNOS boot targets

A boot target is a `make` recipe that produces a kernel image, runs
it on a defined platform, and watches for a fixed set of serial
markers. A target is `passing` only when its smoke script exits
zero with all required markers seen.

## Target list

| Target | Make recipe | Platform | Smoke script | Status |
|---|---|---|---|---|
| QEMU x86_64 OVMF | `nonos-mk-boot-keyring` (existing) and others | `qemu-system-x86_64 -bios OVMF.fd` | `tests/boot/keyring_round_trip.sh` | passing |
| QEMU x86_64 (entropy round-trip) | `nonos-mk-boot-entropy` (planned) | OVMF | `tests/boot/entropy_round_trip.sh` | planned |
| QEMU x86_64 (vfs round-trip) | `nonos-mk-boot-vfs` (planned) | OVMF | `tests/boot/vfs_round_trip.sh` | planned |
| QEMU x86_64 (driver_rng) | `nonos-mk-boot-driver-rng` (planned) | OVMF + virtio-rng device | `tests/boot/driver_rng.sh` | planned |
| QEMU x86_64 (driver_blk) | `nonos-mk-boot-driver-blk` (planned) | OVMF + virtio-blk | `tests/boot/driver_blk_virtio.sh` | planned |
| QEMU x86_64 (driver_net) | `nonos-mk-boot-driver-net` (planned) | OVMF + virtio-net | `tests/boot/driver_net_virtio.sh` | planned |
| QEMU aarch64 virt | `nonos-mk-boot-aarch64-virt` (planned) | `qemu-system-aarch64 -M virt` | `tests/boot/aarch64_virt.sh` | planned |
| QEMU riscv64 virt | `nonos-mk-boot-riscv64-virt` (planned) | `qemu-system-riscv64 -M virt -bios opensbi` | `tests/boot/riscv64_virt.sh` | planned |
| Real x86_64 lab | `nonos-mk-esp` + manual run | UEFI laptop / mini PC / server | `docs/hardware/lab/<machine>.md` | partial |

## Required markers per target

Every target's smoke script must observe at minimum:

```
[ARCH]    boot ok
[MEM]     map ok
[IRQ]     timer ok
[IPC]     ok
[CAPSULE] init ok
[DRIVER]  device list ok
```

A target that adds class-specific behaviour adds class-specific
markers. For example `driver_rng.sh` requires:

```
[DRIVER:rng] claim ok
[DRIVER:rng] mmio mapped
[DRIVER:rng] irq bound
[DRIVER:rng] read 32 bytes
```

## How a target moves from `planned` to `passing`

1. The kernel-side primitives the target needs are real.
2. Any driver capsule the target needs is built and signed.
3. The smoke script exists at the path above.
4. CI runs the script on every push.
5. The matrix row in `hardware_compatibility_matrix.md` is updated.

A row never moves to `qemu` or `production` without all five.

## What "real-hardware proof" means

A real machine is `passing` only when:

- a `docs/hardware/lab/<machine>.md` file exists describing the box, the boot method, and the observed markers
- a serial capture of one boot is attached or referenced
- the QEMU target on the same arch and same boot method is already `passing`

Without QEMU passing first, real-hardware claims are not accepted.

## What is intentionally not a target

- BIOS-only boot on x86_64. NØNOS is UEFI-only.
- Network boot. Boot is always from a local image (USB stick, ESP partition, OVMF disk).
- Multi-kernel boot (kexec / chained loaders). Out of scope.
- Live USB persistence. The OS boots non-persistent by default.
