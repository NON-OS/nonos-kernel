# NØNOS driver capsule matrix

The kernel ships zero device drivers above the broker primitive
boundary. Every driver below is a userland capsule. This file
tracks the planned driver capsules, their dependencies on broker
primitives, and the order they ship.

Status:

- `production`: signed, installed on the default image, passes its smoke marker.
- `prototype`: builds, drives the device under QEMU, no real-hardware proof.
- `build-only`: compiles and is wired into capsule signing/orchestration, but is not spawned.
- `controller-probe`: owns broker grants and reports real controller state, but does not expose a class service yet.
- `designed`: protocol contract written; no code yet.
- `planned`: in scope, no contract.
- `excluded`: intentionally out of scope.

## Order of arrival

The dependency chain for any driver capsule is:

```
broker grant primitives  ->  driver capsule  ->  class-service capsule  ->  app capsules
```

A driver capsule cannot ship before its required broker primitives
are real. The order below reflects that.

| # | Capsule | Class | Required broker primitives | Status | Smoke marker |
|---|---|---|---|---|---|
| 1 | `capsule_driver_rng` | rng | `MkDeviceList`, `MkDeviceClaim`, `MkMmioMap`, `MkIrqBind` | designed | `tests/boot/driver_rng.sh` (planned) |
| 2 | `capsule_driver_blk` | block | + `MkDmaMap`, `MkDmaUnmap` | designed | `tests/boot/driver_blk_virtio.sh` (planned) |
| 3 | `capsule_driver_net` | network | + queue ABI | designed | `tests/boot/driver_net_virtio.sh` (planned) |
| 4 | `capsule_driver_framebuffer` | display | `MkMmioMap` of fb region | designed | `tests/boot/driver_fb.sh` (planned) |
| 5 | `capsule_driver_ps2` | input | `MkPioGrant`, `MkIrqBind` | designed | `tests/boot/driver_ps2.sh` (planned) |
| 6 | `capsule_driver_xhci` | usb_host | + DMA + MSI-X | planned | n/a |
| 7 | `capsule_driver_usb_hid` | input | xHCI capsule + class | planned | n/a |
| 8 | `capsule_driver_nvme` | block/controller | `MkDeviceList`, `MkDeviceClaim`, `MkPciConfigWrite`, `MkMmioMap`, `MkIrqBind` (MSI-X), `MkDmaMap` | admin-identify + SMART health | `driver.nvme0` |
| 9 | `capsule_driver_ahci` | block/controller | `MkDeviceList`, `MkDeviceClaim`, `MkMmioMap`, `MkIrqBind` | controller-probe | `driver.ahci0` |
| 10 | `capsule_driver_e1000` | network | + IRQ sharing | planned | n/a |
| 11 | `capsule_driver_rtl8169` | network | follows e1000 | planned | n/a |
| 12 | `capsule_driver_iwlwifi` | network | + firmware loading | planned | n/a |
| 13 | `capsule_driver_hda` | audio/controller | `MkDeviceList`, `MkDeviceClaim`, `MkMmioMap`, `MkIrqBind` | controller-probe | `driver.hda0` |
| 14 | `capsule_driver_simpledrm` | display | + fb modeset | planned | n/a |
| 15 | `capsule_driver_virtio_gpu` | display | + virtqueue | planned | n/a |

## Service capsules between drivers and apps

| Capsule | Consumes | Exposes | Status |
|---|---|---|---|
| `capsule_storage` | `block.<id>` | filesystem broker endpoint | designed |
| `capsule_net` | `net.<id>` | sockets endpoint | designed |
| `capsule_input` | `input.<id>` | input events endpoint | designed |
| `capsule_display` | `display.<id>` + framebuffer handoff | surface protocol endpoint | designed |
| `capsule_audio` | `audio.<id>` | mixer endpoint | planned |

## ABI per class

Each class has its own protocol JSON schema under `abi/` so a
third-party driver capsule can implement it without reading the
reference driver's source:

| Class | ABI file | Status |
|---|---|---|
| rng | `abi/class_rng.proto.json` | planned |
| block | `abi/class_block.proto.json` | planned |
| network | `abi/class_network.proto.json` | planned |
| display | `abi/class_display.proto.json` | planned |
| input | `abi/class_input.proto.json` | planned |
| audio | `abi/class_audio.proto.json` | planned |

ABI files land alongside the first capsule that implements each
class.

## What the kernel never knows

- which `vendor:device` is a NIC vs. a GPU
- which version of the network stack is running
- which filesystem is mounted
- which display capsule is current
- whether two driver capsules for the same device class are running
- driver-specific recovery, retry, or reconnect policy

The kernel sees pids, capability masks, and broker grants. The rest
is userland.

## What gets a capsule and what does not

A device gets a userland driver capsule when:

- it has a stable bus address (PCI, virt, USB after xHCI)
- the kernel can bound MMIO/PIO/IRQ/DMA for it
- the broker can isolate it from other devices

A device does *not* get a userland driver capsule when:

- it requires raw access to the kernel's address space
- it is the broker's transport (timer, IRQ controller, IOMMU)
- it is the boot recovery surface (serial console)

The boot recovery serial console is the one explicit kernel-side
driver besides the broker itself.
