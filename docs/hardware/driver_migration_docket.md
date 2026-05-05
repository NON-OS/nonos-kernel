# Driver migration docket

The kernel keeps only the broker primitives in `src/drivers/`. Every
real device driver becomes a signed userland capsule under
`userland/capsule_driver_*` that talks to the kernel through the
broker ABI documented in `docs/abi/driver_broker_abi.md`.

This docket tracks every legacy driver tree that lived under
`src/drivers/` before the broker migration started. Reference
sources are recovered into `/tmp/nonos-driver-reference/` (not
committed, not compiled, not imported). The columns name the
broker primitives each capsule will need so the order of work is
visible.

```
+------------+-------------+--------+--------+--------+-----+--------+----------+
|  capsule   |   device    |  MMIO  |  PIO   |  IRQ   | DMA |firmwr  | priority |
+------------+-------------+--------+--------+--------+-----+--------+----------+
| virtio_rng | virtio rng  |  yes   |  no    | optnl  | yes |  no    |    1     |
| virtio_blk | virtio blk  |  yes   |  no    | yes    | yes |  no    |    2     |
| virtio_net | virtio net  |  yes   |  no    | yes    | yes |  no    |    3     |
| framebuf   | bootldr fb  |  yes*  |  no    | no     | no  |  no    |    4     |
| ps2_input  | ps/2 8042   |  no    | yes    | yes    | no  |  no    |    5     |
| nvme       | nvme        |  yes   |  no    | msix   | yes |  no    |    6     |
| xhci       | usb 3       |  yes   |  no    | msix   | yes |  no    |    7     |
| e1000      | intel nic   |  yes   |  no    | msi    | yes |  eeprm |    8     |
| rtl8139    | realtek nic |  some  | yes    | yes    | yes |  no    |    9     |
| rtl8168    | realtek nic |  yes   |  no    | msix   | yes |  no    |    10    |
| ahci       | sata        |  yes   |  no    | msix   | yes |  no    |    11    |
| audio_hda  | hd audio    |  yes   |  no    | yes    | yes |  no    |    12    |
| i2c        | board ctrl  |  yes   |  some  | yes    | no  |  no    |    13    |
| virtio_gpu | virtio gpu  |  yes   |  no    | yes    | yes |  no    |    14    |
| wifi_iwl   | intel wifi  |  yes   |  no    | msix   | yes |  yes   |    15    |
| usb_core   | usb stack   |   --   |   --   |   --   | --  |   --   |  service |
| block_svc  | block stack |   --   |   --   |   --   | --  |   --   |  service |
+------------+-------------+--------+--------+--------+-----+--------+----------+

  *framebuffer comes from the bootloader, not a PCI BAR; broker
   exposes it through a separate `framebuffer_grant` primitive
   (planned), not `MkMmioMap`.

  Legend: msi/msix = needs message-signaled interrupts; eeprm =
  EEPROM read at init; some = driver uses a small PIO range for
  config in addition to MMIO.
```

The rows below expand each driver's broker dependencies, what is
worth recovering from the legacy tree, and what should be discarded
because it was kernel-coupled or written for a monolithic layout.

---

## 1. capsule_driver_virtio_rng — priority 1

| field | value |
|---|---|
| reference source | `/tmp/nonos-driver-reference/virtio_rng/` |
| new capsule name | `userland/capsule_driver_virtio_rng` |
| hardware class | virtio entropy device, PCI vendor 0x1AF4, device 0x1005 (transitional) / 0x1044 (modern) |
| broker syscalls | `MkDeviceList`, `MkDeviceClaim`, `MkMmioMap`, `MkMmioUnmap`, `MkIrqBind`, `MkIrqAck`, `MkIrqPoll`, `MkDmaMap`, `MkDmaUnmap`, `MkDeviceRelease` |
| capabilities | `Driver`, `Mmio`, `Irq`, `Dma` |
| BAR needs | BAR0 modern config (4 KiB common cfg + device cfg), BAR4 notify cfg in modern layout |
| PIO needs | none (modern); transitional supports legacy PIO but the capsule will require modern |
| IRQ needs | one INTx vector (modern PCI virtio) or one MSI-X vector for `requestq` notify |
| DMA needs | one virtqueue (`requestq`) consisting of a descriptor table, available ring, and used ring; the device DMA-reads the descriptor table and DMA-writes random bytes into the buffer the descriptor points at |
| firmware/config | none |
| service endpoint | `entropy.virtio_rng` providing `read_random(buf, len)` |
| recover | PCI ID constants, virtio common-config layout, virtqueue layout |
| discard | direct `crate::memory::*` calls, `EntropyPool` interlock with kernel, the bootstrap path that ran in kernel context |
| QEMU smoke | `-device virtio-rng-pci`; capsule reads N bytes, validates against entropy capsule |
| real hw | uncommon outside cloud; QEMU is the production target |
| blockers | **`MkDmaMap`. Without a broker DMA grant the capsule cannot allocate a virtqueue the device can read or hand the device a real physical address. There is no MMIO-register entropy path on virtio-rng — the whole device is virtqueue-based, so polling-only does not bypass the dependency.** Userland libc also has no broker-syscall bindings yet; that surface lands alongside the first driver capsule. |
| notes | first capsule on the new path; not implementable until `MkDmaMap` exists. The legacy reference under `/tmp/nonos-driver-reference/virtio_rng/` cheated by using kernel virtual addresses as descriptor `addr` fields, which only worked under direct-map and is not safe in capsule context. |

---

## 2. capsule_driver_virtio_blk — priority 2

| field | value |
|---|---|
| reference source | `/tmp/nonos-driver-reference/virtio_blk/` |
| new capsule name | `userland/capsule_driver_virtio_blk` |
| hardware class | virtio block device, PCI vendor 0x1AF4, device 0x1001 / 0x1042 |
| broker syscalls | `MkDeviceList`, `MkDeviceClaim`, `MkMmioMap`, `MkIrqBind`, `MkDmaMap`, `MkDeviceRelease` |
| capabilities | `Driver`, `Mmio`, `Irq`, `Dma` |
| BAR needs | BAR0 common+device cfg, BAR4 notify cfg |
| PIO needs | none (modern) |
| IRQ needs | per-virtqueue MSI-X vector |
| DMA needs | one or more virtqueues; descriptor rings need DMA-coherent memory; no IOMMU on QEMU but `MkDmaMap` is required for real hw |
| firmware/config | none |
| service endpoint | `block.virtio_blk0` providing `read_blocks` / `write_blocks` / `flush` |
| recover | descriptor format, request header, capacity reads |
| discard | the host-side block layer that lived in kernel; replaced by `capsule_block_svc` |
| QEMU smoke | `-drive file=disk.img,if=virtio`; capsule reads/writes blocks, fsync semantics |
| real hw | uncommon outside cloud; QEMU is the production target |
| blockers | `MkIrqBind`, `MkDmaMap`, capsule_block_svc service |
| notes | first DMA-using capsule; lands the broker DMA primitive proof |

---

## 3. capsule_driver_virtio_net — priority 3

| field | value |
|---|---|
| reference source | `/tmp/nonos-driver-reference/virtio_net/` |
| new capsule name | `userland/capsule_driver_virtio_net` |
| hardware class | virtio net device, PCI vendor 0x1AF4, device 0x1000 / 0x1041 |
| broker syscalls | `MkDeviceList`, `MkDeviceClaim`, `MkMmioMap`, `MkIrqBind`, `MkDmaMap`, `MkDeviceRelease` |
| capabilities | `Driver`, `Mmio`, `Irq`, `Dma` |
| BAR needs | BAR0 common+device cfg, BAR4 notify cfg |
| PIO needs | none (modern) |
| IRQ needs | one MSI-X vector per rxq/txq pair |
| DMA needs | rx and tx virtqueues; mergeable rx buffers |
| firmware/config | none |
| service endpoint | `net.virtio_net0` providing `tx_packet`, `rx_packet`, `link_status` |
| recover | feature negotiation order, mergeable-rx handling, MAC read |
| discard | the legacy `crate::network::*` callers that bound it into the kernel |
| QEMU smoke | `-netdev user -device virtio-net-pci`; capsule sends / receives ICMP via NOX network stack |
| real hw | uncommon outside cloud; QEMU is the production target |
| blockers | `MkIrqBind`, `MkDmaMap`, capsule_net service |
| notes | this and `capsule_driver_virtio_blk` together prove DMA + IRQ end to end |

---

## 4. capsule_driver_framebuffer — priority 4

| field | value |
|---|---|
| reference source | `/tmp/nonos-driver-reference/vga/`, `/tmp/nonos-driver-reference/gpu/` |
| new capsule name | `userland/capsule_driver_framebuffer` |
| hardware class | bootloader-supplied framebuffer (UEFI GOP / multiboot); no PCI device behind it on QEMU |
| broker syscalls | a *new* `MkFramebufferMap` primitive (planned, not yet defined) — `MkMmioMap` will not work because the framebuffer is not a PCI BAR |
| capabilities | `Driver`, `Framebuffer` (planned cap) |
| BAR needs | none (memory range comes from the bootloader, kernel records it) |
| PIO needs | none |
| IRQ needs | none |
| DMA needs | none |
| firmware/config | none |
| service endpoint | `display.framebuffer0` providing `present_rect` to the compositor |
| recover | bpp / pitch / pixel-format detection logic |
| discard | the in-kernel font/text-mode renderers (replaced by the compositor) |
| QEMU smoke | `-vga std`; capsule fills the framebuffer with a known pattern, compositor renders it |
| real hw | every UEFI x86_64 board; this is the desktop bootstrap path |
| blockers | the framebuffer broker primitive does not exist yet; design has to follow the same claim/grant model as `MkMmioMap` |
| notes | precondition for any compositor work |

---

## 5. capsule_driver_ps2_input — priority 5

| field | value |
|---|---|
| reference source | `/tmp/nonos-driver-reference/keyboard/` |
| new capsule name | `userland/capsule_driver_ps2_input` |
| hardware class | i8042 PS/2 controller, IO ports 0x60 / 0x64, IRQ 1 (kbd) and IRQ 12 (mouse) |
| broker syscalls | a *new* `MkPioGrant` primitive plus `MkIrqBind` — `MkMmioMap` does not apply to PIO devices |
| capabilities | `Driver`, `Pio` (planned cap), `Irq` |
| BAR needs | none |
| PIO needs | 0x60 (data) and 0x64 (status/cmd), single byte each |
| IRQ needs | IRQ 1 and IRQ 12 |
| DMA needs | none |
| firmware/config | none |
| service endpoint | `input.ps2_kbd`, `input.ps2_mouse` |
| recover | scan-set translation table, capslock/numlock state machine |
| discard | the kernel-side input pipeline that bypassed userland |
| QEMU smoke | `-no-acpi` not necessary; QEMU exposes 8042 by default; capsule observes a key event |
| real hw | every legacy x86 board; absent on most modern UEFI laptops (USB only) |
| blockers | `MkPioGrant`, `MkIrqBind` |
| notes | needed for any pre-USB headless box; on USB-only systems the input path goes via xhci |

---

## 6. capsule_driver_nvme — priority 6

| field | value |
|---|---|
| reference source | `/tmp/nonos-driver-reference/nvme/` |
| new capsule name | `userland/capsule_driver_nvme` |
| hardware class | NVMe SSD, PCI class 0x010802 |
| broker syscalls | `MkDeviceList`, `MkDeviceClaim`, `MkMmioMap`, `MkIrqBind` (MSI-X), `MkDmaMap`, `MkDeviceRelease` |
| capabilities | `Driver`, `Mmio`, `Irq`, `Dma` |
| BAR needs | BAR0/1 (NVMe controller registers, 16 KiB+) |
| PIO needs | none |
| IRQ needs | MSI-X required (legacy INTx not supported by the spec) |
| DMA needs | admin and IO submission/completion queues, PRP lists or SGL |
| firmware/config | controller identify, namespace identify; no external firmware |
| service endpoint | `block.nvme0n1` |
| recover | controller register layout, identify-controller / identify-namespace structures, queue doorbell math |
| discard | kernel-resident block layer integration; `unsafe` direct-mapped DMA buffers |
| QEMU smoke | `-drive if=none,id=nvm,file=disk.img -device nvme,serial=deadbeef,drive=nvm`; capsule does identify, single read |
| real hw | universal on modern laptops/desktops; production target |
| blockers | `MkIrqBind` (MSI-X aware), `MkDmaMap`, capsule_block_svc |
| notes | first serious storage device |

---

## 7. capsule_driver_xhci — priority 7

| field | value |
|---|---|
| reference source | `/tmp/nonos-driver-reference/xhci/`, `/tmp/nonos-driver-reference/usb/` |
| new capsule name | `userland/capsule_driver_xhci` (controller) + `userland/capsule_usbcore` (device model service) |
| hardware class | xHCI USB 3 host controller, PCI class 0x0C0330 |
| broker syscalls | `MkDeviceList`, `MkDeviceClaim`, `MkMmioMap`, `MkIrqBind`, `MkDmaMap`, `MkDeviceRelease` |
| capabilities | `Driver`, `Mmio`, `Irq`, `Dma` |
| BAR needs | BAR0 controller MMIO (operational + capability + runtime + doorbell sub-regions) |
| PIO needs | none |
| IRQ needs | MSI-X primary; MSI fallback |
| DMA needs | event ring, command ring, transfer rings (TRBs), 32/64-bit context structures |
| firmware/config | none generally; some boards ship optional ROMs (irrelevant to the driver) |
| service endpoint | `usbcore.xhci0` for the controller; `input.usb_kbd_*` and `block.usb_msd_*` for class drivers |
| recover | TRB layout, port-status register sequence, slot-context layout |
| discard | the legacy `usb` top-level tree; the new `capsule_usbcore` is a clean rewrite over the broker ABI |
| QEMU smoke | `-device qemu-xhci -device usb-kbd`; capsule observes a port-status event |
| real hw | universal on modern hardware |
| blockers | `MkIrqBind`, `MkDmaMap`, `capsule_usbcore` design |
| notes | xHCI is the gateway for usb-kbd, usb-mouse, usb-msd, usb-net |

---

## 8. capsule_driver_e1000 — priority 8

| field | value |
|---|---|
| reference source | `/tmp/nonos-driver-reference/e1000/` |
| new capsule name | `userland/capsule_driver_e1000` |
| hardware class | Intel 8254x / 82576 family NIC |
| broker syscalls | `MkDeviceList`, `MkDeviceClaim`, `MkMmioMap`, `MkIrqBind` (MSI), `MkDmaMap`, `MkDeviceRelease` |
| capabilities | `Driver`, `Mmio`, `Irq`, `Dma` |
| BAR needs | BAR0 controller MMIO (~128 KiB) |
| PIO needs | none for modern variants |
| IRQ needs | MSI vector |
| DMA needs | rx and tx descriptor rings |
| firmware/config | EEPROM read at init for MAC address |
| service endpoint | `net.e1000_0` |
| recover | descriptor format, EEPROM read sequence, link-status polling |
| discard | direct kernel network-stack integration |
| QEMU smoke | `-device e1000`; capsule reads MAC, sends a single packet |
| real hw | older servers, some embedded boards |
| blockers | `MkIrqBind`, `MkDmaMap`, capsule_net service |
| notes | a useful real-hw target distinct from virtio |

---

## 9. capsule_driver_rtl8139 — priority 9

| field | value |
|---|---|
| reference source | `/tmp/nonos-driver-reference/rtl8139/` |
| new capsule name | `userland/capsule_driver_rtl8139` |
| hardware class | Realtek RTL8139 NIC |
| broker syscalls | `MkDeviceList`, `MkDeviceClaim`, `MkMmioMap`, a *new* `MkPioGrant`, `MkIrqBind`, `MkDmaMap`, `MkDeviceRelease` |
| capabilities | `Driver`, `Mmio`, `Pio`, `Irq`, `Dma` |
| BAR needs | BAR1 MMIO (operational regs); BAR0 PIO range used by some boards |
| PIO needs | per-board: optional 0x100 IO range |
| IRQ needs | legacy INTx |
| DMA needs | a 64 KiB rx ring + tx slot DMA buffers |
| firmware/config | none |
| service endpoint | `net.rtl8139_0` |
| recover | rx-ring wraparound logic, tx-slot allocator |
| discard | the legacy kernel-side ring management |
| QEMU smoke | `-device rtl8139`; capsule sends/receives one packet |
| real hw | obsolete; mostly QEMU |
| blockers | `MkPioGrant`, `MkIrqBind`, `MkDmaMap` |
| notes | useful as the first PIO-using NIC migration |

---

## 10. capsule_driver_rtl8168 — priority 10

| field | value |
|---|---|
| reference source | `/tmp/nonos-driver-reference/rtl8168/` |
| new capsule name | `userland/capsule_driver_rtl8168` |
| hardware class | Realtek RTL8168 / 8169 family NIC |
| broker syscalls | `MkDeviceList`, `MkDeviceClaim`, `MkMmioMap`, `MkIrqBind` (MSI-X), `MkDmaMap`, `MkDeviceRelease` |
| capabilities | `Driver`, `Mmio`, `Irq`, `Dma` |
| BAR needs | BAR2 MMIO (~256 bytes) |
| PIO needs | none |
| IRQ needs | MSI-X |
| DMA needs | descriptor rings |
| firmware/config | none |
| service endpoint | `net.rtl8168_0` |
| recover | descriptor format (slightly different from 8139), pcie config quirks |
| discard | legacy in-kernel binding |
| QEMU smoke | `-device rtl8168` (some QEMU builds); otherwise tested only on real hw |
| real hw | very common on consumer boards |
| blockers | `MkIrqBind`, `MkDmaMap` |
| notes | priority for hardware compatibility once virtio path is proven |

---

## 11. capsule_driver_ahci — priority 11

| field | value |
|---|---|
| reference source | `/tmp/nonos-driver-reference/ahci/` |
| new capsule name | `userland/capsule_driver_ahci` |
| hardware class | SATA AHCI controller |
| broker syscalls | `MkDeviceList`, `MkDeviceClaim`, `MkMmioMap`, `MkIrqBind` (MSI-X), `MkDmaMap`, `MkDeviceRelease` |
| capabilities | `Driver`, `Mmio`, `Irq`, `Dma` |
| BAR needs | BAR5 (ABAR) controller MMIO |
| PIO needs | none |
| IRQ needs | MSI-X |
| DMA needs | command-list + FIS-receive areas + PRDT per command |
| firmware/config | none |
| service endpoint | `block.sata_0` |
| recover | port command-list / FIS layout, NCQ ordering, ATA pass-through framing |
| discard | legacy crypto/erase fast paths that leaked AES into the driver — those move to a separate `capsule_storage_crypto` |
| QEMU smoke | `-device ich9-ahci`; identify + single read |
| real hw | universal on older laptops/desktops; phasing out in favour of NVMe |
| blockers | `MkIrqBind`, `MkDmaMap` |
| notes | preserve NCQ logic; drop everything else |

---

## 12. capsule_driver_audio_hda — priority 12

| field | value |
|---|---|
| reference source | `/tmp/nonos-driver-reference/audio/` |
| new capsule name | `userland/capsule_driver_audio_hda` |
| hardware class | Intel HD-Audio controller |
| broker syscalls | `MkDeviceList`, `MkDeviceClaim`, `MkMmioMap`, `MkIrqBind`, `MkDmaMap`, `MkDeviceRelease` |
| capabilities | `Driver`, `Mmio`, `Irq`, `Dma` |
| BAR needs | BAR0 controller MMIO |
| PIO needs | none |
| IRQ needs | one IRQ vector |
| DMA needs | CORB / RIRB / Buffer Descriptor List per stream |
| firmware/config | none generally; some codecs need verb sequences |
| service endpoint | `audio.hda0` |
| recover | codec verb tables, stream descriptor layout |
| discard | direct kernel mixer; userland audio service owns mixing |
| QEMU smoke | `-device intel-hda -device hda-output`; capsule plays a 1 kHz tone |
| real hw | universal on x86 |
| blockers | `MkIrqBind`, `MkDmaMap` |
| notes | low priority; audio is desktop polish, not a system gate |

---

## 13. capsule_driver_i2c — priority 13

| field | value |
|---|---|
| reference source | `/tmp/nonos-driver-reference/i2c/` |
| new capsule name | `userland/capsule_driver_i2c` |
| hardware class | board I²C / SMBus controller (varies; PIIX4, ICH, designware are typical) |
| broker syscalls | `MkDeviceList`, `MkDeviceClaim`, `MkMmioMap` or `MkPioGrant` depending on controller, `MkIrqBind`, `MkDeviceRelease` |
| capabilities | `Driver`, `Mmio` and/or `Pio`, `Irq` |
| BAR needs | controller-specific |
| PIO needs | controller-specific |
| IRQ needs | one vector |
| DMA needs | none |
| firmware/config | none |
| service endpoint | `i2c.bus_<N>` |
| recover | controller-specific FSM logic |
| discard | direct calls into kernel sensor/EC code |
| QEMU smoke | limited; QEMU only models PIIX4/ICH SMBus narrowly |
| real hw | every modern x86 board has at least one |
| blockers | `MkIrqBind`, possibly `MkPioGrant` |
| notes | low priority unless an EC or board-sensor capsule needs it |

---

## 14. capsule_driver_virtio_gpu — priority 14

| field | value |
|---|---|
| reference source | `/tmp/nonos-driver-reference/gpu/` |
| new capsule name | `userland/capsule_driver_virtio_gpu` |
| hardware class | virtio GPU, PCI vendor 0x1AF4 device 0x1050 |
| broker syscalls | `MkDeviceList`, `MkDeviceClaim`, `MkMmioMap`, `MkIrqBind`, `MkDmaMap`, `MkDeviceRelease` |
| capabilities | `Driver`, `Mmio`, `Irq`, `Dma` |
| BAR needs | BAR0 common cfg, BAR4 notify cfg |
| PIO needs | none |
| IRQ needs | one vector |
| DMA needs | controlq + cursorq virtqueues; resource attach via DMA-coherent buffers |
| firmware/config | none |
| service endpoint | `display.virtio_gpu0` |
| recover | resource create / attach / set-scanout sequence |
| discard | the legacy in-kernel scanout fast paths |
| QEMU smoke | `-device virtio-gpu-pci`; capsule presents a solid-colour scanout |
| real hw | none — QEMU only |
| blockers | `MkIrqBind`, `MkDmaMap`, the compositor capsule |
| notes | preferred replacement for the framebuffer capsule on QEMU once the compositor is in |

---

## 15. capsule_driver_wifi_iwl — priority 15

| field | value |
|---|---|
| reference source | `/tmp/nonos-driver-reference/wifi/` |
| new capsule name | `userland/capsule_driver_wifi_iwl` (Intel iwlwifi family); other vendors get separate capsules |
| hardware class | PCIe Wi-Fi NIC |
| broker syscalls | `MkDeviceList`, `MkDeviceClaim`, `MkMmioMap`, `MkIrqBind` (MSI-X), `MkDmaMap`, `MkDeviceRelease` |
| capabilities | `Driver`, `Mmio`, `Irq`, `Dma` |
| BAR needs | BAR0 controller MMIO |
| PIO needs | none |
| IRQ needs | MSI-X |
| DMA needs | TX/RX rings + command rings; large DMA-coherent regions |
| firmware/config | per-device firmware blob loaded over a host command path; firmware bundle has its own signing |
| service endpoint | `net.wifi_<dev_id>` |
| recover | command-queue framing; firmware-load sequence as documentation only |
| discard | nearly everything — the legacy tree was an exploration, not a working driver |
| QEMU smoke | none — QEMU does not model real wifi |
| real hw | mandatory for laptops, hardest target on the list |
| blockers | a firmware-grant primitive (planned), `MkIrqBind`, `MkDmaMap`, mac80211-equivalent userland stack |
| notes | last on the list intentionally; no production claim until the full chain is in |

---

## Service capsules (no hardware claim)

These rows are not driver capsules but the userland services the
drivers feed. They are listed so the dependency picture is complete.

| service | role |
|---|---|
| `capsule_block_svc` | block-device routing; multiplexes `block.*` capsules to `vfs_capsule` |
| `capsule_net_svc` | NIC routing + L2/L3 + socket plumbing for NOX |
| `capsule_usbcore` | USB device model on top of host controllers |
| `capsule_input_svc` | merges input streams into a single event bus the compositor consumes |

These are not under driver priority order; they land alongside
their first consumer.

---

## What gets discarded outright

Anywhere in the legacy tree the following appeared, it does not
come back:

- direct `crate::memory::*` calls from a driver (drivers receive
  memory through the broker, not by reaching into the allocator)
- driver-side crypto (storage encryption is a separate capsule)
- driver-side filesystem code (lives in `capsule_block_svc` /
  `capsule_vfs`)
- in-kernel rendering, mixing, or input event distribution (lives
  in compositor / audio service / input service)
- `EntropyPool` interlocks that gave drivers a kernel-resident hook
- ad-hoc `unsafe { *(addr as *mut u32) }` MMIO accesses; capsule
  drivers use the typed `Mmio<T>` accessor that the broker hands
  out alongside the grant

## Order of operations

1. `MkIrqBind` is in (legacy INTx via IO-APIC, polling-only
   notification, BSP delivery only). It unblocks the IRQ wiring of
   any subsequent driver capsule but does not on its own enable
   any virtio device — those need DMA.
2. **`MkDmaMap` is the next gate.** Every virtio device on the
   priority list — including `virtio_rng` — uses a virtqueue with
   descriptor rings the device DMA-reads. Without `MkDmaMap` no
   honest virtio driver capsule can be written. There is no
   register-only entropy path on virtio-rng.
3. Land userland-libc broker bindings (wrappers around
   `MkDeviceList`, `MkDeviceClaim`, `MkMmioMap`, `MkIrqBind`,
   `MkIrqAck`, `MkIrqPoll`, `MkDmaMap`, `MkDeviceRelease`) so the
   first driver capsule has an ABI to call. Today no userland
   crate uses any broker syscall.
4. With `MkDmaMap` and the libc bindings in, build
   `capsule_driver_virtio_rng` first (the simplest virtqueue
   shape), then `capsule_driver_virtio_blk` and
   `capsule_driver_virtio_net`.
5. The framebuffer + ps2_input capsules need their own broker
   primitives (`MkFramebufferMap`, `MkPioGrant`); land those before
   touching the row.
6. Real hardware drivers (nvme, xhci, ahci, e1000, rtl8168) follow
   priority order, each gated by a real-hw boot test, not just
   QEMU.

The static gate `src/drivers/ contains only pci/security/virtio_rng`
prevents any of the legacy trees from coming back into the kernel
image. The reference under `/tmp/nonos-driver-reference/` is read
by humans, never by the build.
