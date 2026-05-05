# Hardware broker

The kernel does not own drivers. Drivers run as userland capsules.
The kernel keeps a single hardware-side primitive: the broker, which
mediates every privileged hardware operation a driver capsule
issues.

The broker is the kernel's only driver-facing surface. A driver
capsule cannot:

- map MMIO without a broker grant
- read or write a PIO port without a broker grant
- bind an IRQ vector without a broker grant
- create a DMA window without a broker grant

A capsule that crashes loses every grant immediately; the broker
walks the per-pid grant table on `MkExit` and revokes.

## 1. Responsibilities

What the broker does:

- enumerates buses (PCI on x86_64, DTB-derived on aarch64/riscv64,
  ACPI for non-PCI legacy devices on x86_64)
- assigns each device a stable kernel-side `device_id`
- exposes a read-only metadata view (vendor, device, class, BARs,
  capabilities, IRQ pins)
- claims devices to driver capsules on a first-come basis, gated by
  cap and by a manifest match
- grants MMIO ranges per claim, validated against the device's
  declared BARs
- grants PIO ranges per claim
- binds IRQ vectors per claim, routing through the platform IRQ
  controller (APIC on x86_64, GIC on aarch64, PLIC on riscv64)
- creates DMA windows, programming the IOMMU when present and
  bouncing through SWIOTLB-style ranges when not
- revokes every grant when a claim is released or the holding pid
  exits

What the broker does not do:

- parse vendor-specific protocols
- format requests for a device
- implement retry, reconnect, or recovery semantics
- adjudicate which driver "should" own a device (the policy is
  manifest-driven; the broker only checks the match)
- expose register-level access to non-driver capsules

## 2. Object model

Every claim is a tuple:

```
Claim {
    pid:        u32         // owning capsule pid
    device_id:  u64         // broker-assigned, stable across the boot
    grants:     Vec<Grant>  // MMIO, PIO, IRQ, DMA
    epoch:      u64         // bumps on release; clients holding a
                            // stale (claim, epoch) get EPERM
}

Grant {
    kind:       GrantKind   // Mmio | Pio | Irq | Dma
    handle:     u64         // opaque, returned to the driver
    bounds:     GrantBounds // range or vector
}
```

The grant `handle` is what the driver passes back when releasing or
when invoking subsequent broker calls. The broker never trusts a
range or vector from the driver payload alone; it always looks the
grant up by handle and re-checks against the original claim.

## 3. Capability model

| Cap | Granted to | Granted by |
|---|---|---|
| `CAP_DEVICE_ENUM` | every driver capsule, plus a few inspection capsules | install time |
| `CAP_DRIVER` | a driver capsule | install time, scoped to the device class in the manifest |
| `CAP_MMIO` | a driver capsule | install time; bounded by the broker per-grant |
| `CAP_PIO` | a driver capsule | install time |
| `CAP_IRQ` | a driver capsule | install time |
| `CAP_DMA` | a driver capsule | install time |
| `CAP_IOMMU` | the broker's own internal use; not granted to userland | n/a |
| `CAP_FRAMEBUFFER` | `capsule_display` | install time, exclusive |
| `CAP_INPUT_DRAIN` | `capsule_input` | install time, exclusive |
| `CAP_BLOCK` | `capsule_storage` and block driver capsules | install time |
| `CAP_NETWORK` | the network capsule and NIC driver capsules | install time |

Holding `CAP_DRIVER` alone does not let a capsule claim a device.
The capsule must also (a) hold the device-class cap, (b) match the
claim manifest, and (c) be the first to call `MkDeviceClaim`.

## 4. Cross-driver isolation

The broker enforces:

- a NIC driver cannot map a GPU's MMIO BARs (the grant is bounded
  to the claimed device's declared ranges)
- a storage driver cannot bind keyboard IRQs (the IRQ grant is
  bounded to the device's declared IRQ pin)
- a driver cannot peek at another driver's grants (the per-pid
  grant table is not exposed across pids)
- a DMA window granted to driver A is not visible from driver B's
  IOMMU domain

## 5. IRQ ownership

On x86_64, the broker requests a vector from the per-CPU vector
allocator and programs the local APIC's redirection table. The IRQ
handler runs in kernel mode briefly, then signals the driver
capsule through a per-IRQ semaphore endpoint. The driver capsule
drains the semaphore on its own thread.

On aarch64 and riscv64 the same shape applies with GIC and PLIC
respectively. The driver-facing API is the same: a kernel
semaphore endpoint that wakes the driver thread.

## 6. DMA ownership

When an IOMMU is present the broker creates an isolated domain per
claim. Bus addresses returned to the driver are valid only inside
that domain. A driver writing to an address outside its domain
takes an IOMMU fault that the broker logs and surfaces as `EFAULT`
on the next driver syscall.

When no IOMMU is present the broker allocates from a per-claim
bounce region in the kernel's reserved DMA pool. Bus addresses are
physical kernel addresses; the broker pins the pages and maps them
read-write into the driver's address space. On grant release the
pages are zeroed and returned to the pool.

## 7. Claim release

Three release paths:

1. The driver calls `MkDeviceRelease(device_id)`. The broker walks
   the claim's grants in reverse, unmaps MMIO, unbinds the IRQ,
   tears down the DMA domain, and removes the claim entry. The
   epoch bumps so any in-flight grant lookup fails with `ESTALE`.
2. The driver pid exits. The kernel's exit path calls into the
   broker's pid-walk hook; same teardown as above.
3. An IOMMU fault on an in-flight DMA (driver bug) revokes all of
   that claim's grants and signals the driver to exit. The broker
   does not attempt to recover the device state.

## 8. Boot-only drivers

Two drivers run inside the kernel during early boot, before any
userland is alive:

- the serial console driver (port I/O on x86_64, MMIO UART on
  aarch64/riscv64) for the recovery console
- the boot RNG path (virtio-rng on QEMU, RDRAND/RDSEED on real
  x86_64)

These are not "drivers" in the userland-capsule sense; they are
trusted-path kernel code. They are documented as `BOOT_ONLY` in
the driver map and disappear from kernel scope once a replacement
capsule is alive (planned: `capsule_driver_rng`,
`capsule_driver_serial_console`).

The broker itself is in scope from the moment the PCI scan
completes; that is the only kernel-side driver framework.

## 9. What the broker is not

- not a hot-plug manager (a hot-plug event signals
  `capsule_driver_orchestrator` over IPC; the broker only updates
  its device table)
- not a power manager (P/D states are the platform driver's
  business, again a userland capsule)
- not a generic resource governor (rate limiting, fair scheduling,
  per-device QoS belong in the relevant capsule, not in the kernel
  hardware boundary)
