# NØNOS hardware compatibility matrix

Status values used in every row:

- `production`: passes both QEMU smoke and at least one real-hardware proof, on the active build.
- `qemu`: passes QEMU smoke; no real-hardware proof yet.
- `integrated`: source compiles into the active build, no smoke run yet.
- `designed`: contract written under `docs/architecture` or `abi/`, no code yet.
- `missing`: not in scope yet.
- `excluded`: intentionally not supported.

A row is `production` only when both proof files exist under `tests/boot/` (QEMU) and `docs/hardware/lab/` (real machine).

## CPU and platform primitives

| Class | Kernel primitive | Userland capsule | Status | QEMU proof | Hardware proof | Blocker | Next slice |
|---|---|---|---|---|---|---|---|
| CPU bring-up x86_64 | `arch::x86_64::boot::init` | none | production | yes | yes (one Intel UEFI box) | none | none |
| CPU bring-up aarch64 | `arch::aarch64::boot::init` | none | integrated | no | no | no QEMU virt run | H4 |
| CPU bring-up riscv64 | `arch::riscv64::boot::init` | none | integrated | no | no | no QEMU virt run | H4 |
| Timer x86_64 | `sys::timer::tsc` + APIC timer | none | qemu | yes | partial | needs real-machine TSC invariance audit | H5 |
| Timer aarch64 | `arch::aarch64::timer` | none | integrated | no | no | bring-up | H4 |
| Timer riscv64 | `arch::riscv64::timer` | none | integrated | no | no | bring-up | H4 |
| Interrupt controller x86_64 | local APIC + IO-APIC | none | qemu | yes | partial | real-hardware MSI audit | H5 |
| Interrupt controller aarch64 | GIC | none | integrated | no | no | bring-up | H4 |
| Interrupt controller riscv64 | PLIC + CLINT | none | integrated | no | no | bring-up | H4 |
| Memory map (E820/EFI) | `arch::x86_64::memory` | none | qemu | yes | yes | none | none |
| Memory map DTB (aarch64/riscv64) | `arch::<arch>::memory` | none | integrated | no | no | bring-up | H4 |
| Paging x86_64 | `memory::paging` | none | qemu | yes | yes | none | none |
| Paging aarch64 (TTBR0/1, 4K) | `arch::aarch64::mmu` | none | integrated | no | no | bring-up | H4 |
| Paging riscv64 (Sv39/Sv48) | `arch::riscv64::mmu` | none | integrated | no | no | bring-up | H4 |
| Framebuffer handoff | `boot::handoff::BootHandoffV1` | `capsule_display` | qemu | partial | partial | display capsule not built | H3 |
| Serial recovery x86_64 | `sys::serial` (16550 PIO) | future `capsule_driver_serial` | production | yes | yes | none | none |
| Serial recovery aarch64 | PL011 MMIO | future `capsule_driver_serial` | integrated | no | no | bring-up | H4 |
| Serial recovery riscv64 | NS16550 MMIO | future `capsule_driver_serial` | integrated | no | no | bring-up | H4 |

## Buses and discovery

| Class | Kernel primitive | Userland capsule | Status | QEMU proof | Hardware proof | Blocker | Next slice |
|---|---|---|---|---|---|---|---|
| PCI/PCIe (x86_64) | `bus::pci` + `drivers::pci` | none | qemu | yes | partial | real machine BAR scan audit | H5 |
| PCI/PCIe (aarch64) | DTB-derived ECAM | none | designed | no | no | DTB walker | H4 |
| ACPI tables | `boot::firmware` (RSDP/XSDT/MADT) | future `capsule_acpi_query` | qemu | yes | partial | none | H5 |
| DTB | `arch::<arch>::dtb` | future `capsule_dtb_query` | designed | no | no | not started | H4 |
| IOMMU (Intel VT-d / AMD-Vi) | `memory::iommu` | none | designed | no | no | broker grant integration | H2 |
| IOMMU (SMMUv3) | aarch64 backend | none | designed | no | no | aarch64 bring-up | H4 |
| MMIO authority | `hardware::broker` (claim + grant) | none | designed | no | no | `MkMmioMap` | H2 |
| PIO authority | `hardware::broker` (PIO grant) | none | designed | no | no | `MkPioGrant` | H2 |
| IRQ routing | `hardware::broker` + arch IRQ controller | none | designed | no | no | `MkIrqBind` per arch | H2/H4 |
| DMA mapping | `hardware::broker` + IOMMU | none | designed | no | no | `MkDmaMap` | H2 |

## Entropy

| Class | Kernel primitive | Userland capsule | Status | QEMU proof | Hardware proof | Blocker | Next slice |
|---|---|---|---|---|---|---|---|
| RDRAND/RDSEED | `crypto::util::rng::entropy::hardware` | none (boot only) | production | yes | yes | none | none |
| virtio-rng | `drivers::virtio_rng` | future `capsule_driver_rng` | qemu | yes | n/a | broker grant primitives | H3 |
| Bootloader-supplied entropy | `BootHandoffV1::boot_entropy` | none | qemu | yes | partial | bootloader spec | H5 |
| TPM RNG | none (legacy code deleted) | future `capsule_driver_tpm` | designed | no | no | TPM driver capsule design | post-H3 |

## Block / storage

| Class | Kernel primitive | Userland capsule | Status | QEMU proof | Hardware proof | Blocker | Next slice |
|---|---|---|---|---|---|---|---|
| virtio-blk | broker grants only | `capsule_driver_blk` | designed | no | n/a | broker grant + capsule | H3 |
| NVMe | broker grants only | `capsule_driver_nvme` | admin-identify + SMART health | build-only | no | IO queues + PRP/SGL data path before block service | next storage slice |
| AHCI/SATA | broker grants only | `capsule_driver_ahci` | controller-probe | build-only | no | command-list/FIS/PRDT DMA before block service | next driver slice |
| SD/eMMC | broker grants only | `capsule_driver_sdmmc` | missing | no | no | aarch64 boards | post-H4 |

## Network

| Class | Kernel primitive | Userland capsule | Status | QEMU proof | Hardware proof | Blocker | Next slice |
|---|---|---|---|---|---|---|---|
| virtio-net | broker grants only | `capsule_driver_net` (virtio backend) | designed | no | n/a | broker grants + capsule | H3 |
| e1000/e1000e | broker grants only | `capsule_driver_e1000` | raw-frame + telemetry | no | no | QEMU boot smoke + hardware proof | next network slice |
| RTL8139/8169 | broker grants only | `capsule_driver_rtl8139` / `capsule_driver_rtl8169` | raw-frame + telemetry | no | no | QEMU boot smoke + hardware proof | next network slice |
| Intel iwlwifi | broker grants only | `capsule_driver_iwl` | missing | no | no | firmware loading model | post-H4 |
| WiFi generic | broker grants only | `capsule_driver_wifi_<vendor>` | missing | no | no | per-vendor | post-H4 |
| Bluetooth | broker grants only | `capsule_driver_bt_<vendor>` | missing | no | no | per-vendor | post-H4 |
| Network stack | none in kernel | `capsule_net` | designed | no | no | sits on driver_net | H3 |

## Input / display

| Class | Kernel primitive | Userland capsule | Status | QEMU proof | Hardware proof | Blocker | Next slice |
|---|---|---|---|---|---|---|---|
| PS/2 keyboard/mouse | broker grants only | `capsule_driver_ps2_input` | keyboard + AUX mouse events with controller telemetry | no | n/a | QEMU keyboard/mouse injection smoke | run input smoke |
| USB HID keyboard | broker grants only | `capsule_driver_usb_hid` | missing | no | no | xHCI capsule first | post-H3 |
| USB HID pointer | broker grants only | `capsule_driver_usb_hid` | missing | no | no | xHCI capsule first | post-H3 |
| USB host (xHCI) | broker grants only | `capsule_driver_xhci` | controller bring-up + slot lifecycle | no | no | Address Device + endpoint-zero control transfers | next USB slice |
| USB host (EHCI/UHCI/OHCI) | broker grants only | `capsule_driver_<host>` | excluded | n/a | n/a | xHCI is the only target | n/a |
| Framebuffer (UEFI GOP) | `BootHandoffV1::fb` | `capsule_display` | qemu | partial | partial | display capsule | H3 |
| simpledrm | broker grants only | `capsule_driver_simpledrm` | missing | no | no | follows display capsule | post-H3 |
| virtio-gpu | broker grants only | `capsule_driver_virtio_gpu` | missing | no | no | display capsule first | post-H3 |
| Intel/AMD/NV GPU | broker grants only | `capsule_driver_<vendor>` | missing | no | no | per-vendor | far future |

## Audio

| Class | Kernel primitive | Userland capsule | Status | QEMU proof | Hardware proof | Blocker | Next slice |
|---|---|---|---|---|---|---|---|
| AC'97 | broker grants only | `capsule_driver_ac97` | missing | no | no | per-codec | post-H3 |
| Intel HDA | broker grants only | `capsule_driver_hda` | controller-probe | build-only | no | CORB/RIRB + stream DMA before audio service | next driver slice |
| virtio-snd | broker grants only | `capsule_driver_virtio_snd` | missing | no | no | follows virtio-net path | post-H3 |

## Filesystem

| Class | Kernel primitive | Userland capsule | Status | QEMU proof | Hardware proof | Blocker | Next slice |
|---|---|---|---|---|---|---|---|
| RAM-only ramfs | none (kernel-side ramfs capsule mirror) | `capsule_ramfs` | qemu | yes | yes | none | none |
| ext4 read | none (legacy code deleted) | future `capsule_fs_ext4` | missing | no | no | block driver capsule first | post-H3 |
| FAT32 | none | future `capsule_fs_fat32` | missing | no | no | block driver capsule first | post-H3 |
| ext4 write / journal | none | future `capsule_fs_ext4` | missing | no | no | follows ext4 read | post-H3 |
| btrfs / xfs / zfs | none | not in scope yet | excluded | n/a | n/a | n/a | n/a |
| Storage encryption | provided by `capsule_crypto` | `capsule_fs_<name>` opt-in | designed | no | no | per-filesystem capsule | post-H3 |

## Power / battery

| Class | Kernel primitive | Userland capsule | Status | QEMU proof | Hardware proof | Blocker | Next slice |
|---|---|---|---|---|---|---|---|
| ACPI battery | none | `capsule_acpi_query` | missing | no | no | ACPI query capsule | post-H4 |
| ACPI thermal | none | `capsule_acpi_query` | missing | no | no | ACPI query capsule | post-H4 |
| C-states / P-states | none | `capsule_driver_cpufreq` | missing | no | no | per-vendor | post-H4 |
| Reboot / poweroff | broker grants only | `capsule_acpi_query` | missing | no | no | ACPI query capsule | post-H3 |
