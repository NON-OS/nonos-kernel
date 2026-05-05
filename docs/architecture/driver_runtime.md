# Driver runtime

A driver is a userland capsule signed by a publisher whose key is
in the local registry. It owns one device or one device class. It
talks to the kernel only through the broker (hardware side) and
exposes one or more class-service endpoints on the userland side.

```
[manifest claim]   install-time, names device class
       |
       v
[broker enumerate] device shows in device table on bus scan
       |
       v
[supervisor spawn] driver capsule pid created
       |
       v
[MkDeviceClaim]    cap-gated, manifest-matched, first-come
       |
       v
[grants]           MkMmioMap, MkIrqBind, MkDmaMap as needed
       |
       v
[serve]            class IPC endpoints (block, net, display,
                    input, audio, rng, ...)
       |
       +-- crash ---> broker auto-revoke
       |              orchestrator decides:
       |              restart | failover | give-up | block-class
       |
       v
[MkDeviceRelease]  driver done, grants rolled back, epoch bumps
```

Driver capsules and app capsules use the same load path, the same
manifest format, the same capability model, and the same crash
isolation rules. The only difference is the cap set and the
broker access it implies.

## 1. Lifecycle

```
1. install:   capsule_installer verifies the driver manifest and
              checks that the publisher key has the driver-class
              authority for the declared device classes.
2. spawn:     the kernel loads the ELF and grants the cap mask
              the manifest declared and the user approved.
3. enumerate: the driver calls MkDeviceList(class) to find a
              matching device.
4. claim:     the driver calls MkDeviceClaim(device_id, manifest_hash).
              The broker checks vendor/device IDs against the
              manifest's declared support set.
5. grant:     the driver requests MMIO / PIO / IRQ / DMA grants in
              the order it needs them. The broker validates each
              against the claimed device's declared ranges.
6. serve:     the driver registers its class-service endpoint(s)
              and answers requests from client capsules.
7. exit:      the driver calls MkDeviceRelease, then MkExit. The
              broker's per-pid hook also fires on involuntary
              exit.
```

A driver is not a singleton. Two NIC driver capsules, signed by
different publishers, can run side by side as long as they claim
different devices.

## 2. Crash policy

A driver crash kills the driver pid and revokes every grant. Three
configurable behaviours follow the crash, declared in the driver
manifest's `crash_policy`:

- `kill`: do not restart. The device sits unowned.
- `restart`: an orchestrator capsule (`capsule_driver_orchestrator`)
  sees the death and respawns the driver after an exponential
  backoff. After three restarts inside one boot, the policy
  switches to `kill` until the user clicks retry.
- `failover`: the orchestrator picks the next-priority manifest
  for the same device class and spawns it.

The kernel does not observe any of this; the orchestrator capsule
implements the policy. The kernel's role is `MkExit` cleanup.

## 3. Class services

Each driver implements a class service. Classes today:

| Class | Driver capsule | Service endpoint | Client |
|---|---|---|---|
| `block` | virtio_blk, NVMe, AHCI | `block.<device_id>` | `capsule_storage` |
| `network` | virtio_net, e1000, RTL8169 | `net.<device_id>` | `capsule_net` |
| `display` | virtio_gpu, framebuffer | `display.<device_id>` | `capsule_display` |
| `input` | PS/2, USB HID | `input.<device_id>` | `capsule_input` |
| `audio` | virtio_snd, AC'97 | `audio.<device_id>` | `capsule_audio` |
| `rng` | virtio_rng | `rng.<device_id>` | `capsule_entropy` |

The class service ABI is per-class, defined under
`abi/class_<name>.proto.json`. The driver capsule implements the
server side; the corresponding service capsule implements the
client side. App capsules never talk to a driver directly; they
go through the service capsule.

## 4. Device-to-driver matching

A driver manifest declares a list of `(vendor_id, device_id, class)`
triples it supports. The orchestrator maintains a priority list per
class. On enumerate, the orchestrator picks the highest-priority
manifest whose declared support set matches. If nothing matches, the
device is left unclaimed; user-installable third-party drivers can
be added later.

A user can pin a specific driver to a specific device through
`capsule_settings`; the orchestrator honours pins.

## 5. Grants are per-claim

Every grant is scoped to one claim. A driver that holds two claims
(two devices of the same class) holds two independent grant tables.
The broker rejects any cross-claim grant lookup; releasing one claim
does not affect another.

## 6. DMA bounds

A driver declares `max_dma_window` in its manifest. The broker
refuses DMA mappings that would exceed the declared window (sum of
in-flight maps). When the IOMMU is present this is enforced at the
hardware level; without IOMMU the broker tracks the in-flight bytes
and rejects mappings that would cross the budget.

## 7. Trust model

The driver capsule sees its device's MMIO/PIO/IRQ/DMA. The kernel
trusts the driver to drive that one device correctly. The kernel
does not trust the driver with any other device, with the address
space of any other capsule, or with the kernel's own memory:

- an MMIO fault outside the granted range is `EFAULT`
- an IRQ outside the bound vector is silently dropped
- a DMA write outside the granted window is an IOMMU fault on
  IOMMU systems and a broker-rejected map on non-IOMMU systems
- a misbehaving driver that crashes loses every grant

This is the same trust shape as a normal app capsule, scaled up to
the hardware boundary.

## 8. ABI versioning

The broker exposes an `abi_version` integer through `MkDeviceList`.
Drivers refuse to start if `abi_version < their_min`. Bumping the
broker ABI requires a coordinated release of the kernel and the
driver capsules; the userland orchestrator can pin per-driver
versions during transition windows.

## 9. Boot-only carve-outs

Two paths run inside the kernel during early boot:

- serial recovery console
- early entropy (RDRAND/RDSEED on x86_64; virtio-rng under QEMU)

Both are kernel-resident only until their replacement driver
capsules are alive and proven. The kernel-side virtio-rng exits
its read path the moment `capsule_driver_rng` registers a `rng.*`
endpoint; after that, the kernel's only RNG seed source is the
boot-handoff entropy field plus periodic reseeds from the rng
service. Same shape applies to the serial console.
