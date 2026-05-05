# Driver broker syscall ABI

The kernel exposes hardware to userland through eleven syscalls.
They form one closed surface: list a device, claim it, map a slice
of one of its BARs, bind a device IRQ to a kernel-delivered
notification slot, ack the IRQ once it has been serviced, allocate
a DMA-coherent buffer the device can read or write through, drop
any of those grants, give the device back. No other path turns
physical memory into a user mapping, carries an interrupt into
userland, or hands a capsule a buffer the hardware can DMA.

```
   userland                    kernel                    PCI / ACPI
   --------                    ------                    ----------
   MkDeviceList   ----->  broker::table::list      <-----  PCI scan
                          (DeviceRecord[])

   MkDeviceClaim  ----->  broker::claim::claim
                          (pid, device_id, epoch)

   MkMmioMap      ----->  broker::mmio::map_for_caller
                          - epoch fresh?
                          - BAR is MMIO?
                          - range inside BAR?
                          - alignment ok?
                          - reserve user VA
                          - install user/uncached/NX pages
                          - record MmioGrant
                          <-----  user_va, length, grant_id

   MkMmioUnmap    ----->  broker::mmio::unmap_grant
                          - drop pages, shoot TLB
                          - drop grant record

   MkDeviceRelease ----->  broker::mmio::release_for_device
                          (drop every grant tied to the device)
                           broker::claim::release
                          (drop the claim)
```

## Capability split

| Syscall          | Required cap       |
|------------------|--------------------|
| MkDeviceList     | `DeviceEnum`       |
| MkDeviceClaim    | `Driver`           |
| MkDeviceRelease  | `Driver`           |
| MkMmioMap        | `Mmio`             |
| MkMmioUnmap      | `Mmio`             |
| MkIrqBind        | `Irq`              |
| MkIrqUnbind      | `Irq`              |
| MkIrqAck         | `Irq`              |
| MkIrqPoll        | `Irq`              |
| MkDmaMap         | `Dma`              |
| MkDmaUnmap       | `Dma`              |

`Admin` implies all of the above. Enumeration authority is separate
from claim authority; claim authority is separate from mapping
authority. A capsule that only needs to list devices does not need
the right to map MMIO.

`Irq` (bit `1 << 18`) gates all four `MkIrq*` syscalls. `Dma` (bit
`1 << 19`) gates `MkDmaMap` / `MkDmaUnmap`. Driver capsules typically
hold the full `Driver | Mmio | Irq | Dma` bundle; manifest and
spawn graph decide which capsule gets which bits.

## Capability bits

```
DeviceEnum   = 1 << 15   (32768)
Driver       = 1 << 16   (65536)
Mmio         = 1 << 17   (131072)
Irq          = 1 << 18   (262144)
Dma          = 1 << 19   (524288)
```

## Syscall numbers

```
MkDeviceList    = 0x1040
MkDeviceClaim   = 0x1041
MkDeviceRelease = 0x1042
MkMmioMap       = 0x1043
MkMmioUnmap     = 0x1044
MkIrqBind       = 0x1045
MkIrqUnbind     = 0x1046
MkIrqAck        = 0x1047
MkIrqPoll       = 0x1048
MkDmaMap        = 0x1049
MkDmaUnmap      = 0x104A
```

## MkDeviceList

```
i64 MkDeviceList(class: u32, buf: *mut DeviceRecord, count: u64);
```

Three argument words. `count == 0` is the probe form: returns the
number of records the broker would write for `class`, no user-buffer
access. Otherwise writes up to `count` records and returns the
number written. `class == 0` means no filter.

`DeviceRecord` (176 bytes) is documented in
`src/hardware/broker/device.rs`. Its fixed layout is asserted at
compile time; userland builds against the same struct.

Errors:

| value  | name      | meaning                                    |
|--------|-----------|--------------------------------------------|
| `-14`  | EFAULT    | `count != 0` and `buf` is null or invalid  |
| `-22`  | EINVAL    | `count * 176` would overflow               |

## MkDeviceClaim

```
i64 MkDeviceClaim(device_id: u64);
```

One argument word. Claims `device_id` for the calling pid. Returns
the granted epoch on success; the same epoch must be supplied on
every later `MkMmioMap` call against this claim.

Errors:

| value  | name      | meaning                                    |
|--------|-----------|--------------------------------------------|
| `-1`   | EPERM     | no current pid                             |
| `-16`  | EBUSY     | device already claimed                     |
| `-19`  | ENODEV    | unknown `device_id`                        |
| `-22`  | EINVAL    | claim table inconsistent (kernel bug)      |

## MkDeviceRelease

```
i64 MkDeviceRelease(device_id: u64);
```

One argument word. Releases the holder's claim on `device_id`. Any
outstanding MMIO grants for the device are revoked first; the
caller's CR3 is active here so the unmap and TLB shootdown happen
in-context.

Errors:

| value  | name      | meaning                                    |
|--------|-----------|--------------------------------------------|
| `-1`   | EPERM     | not the holder                             |
| `-19`  | ENODEV    | claim does not exist                       |
| `-22`  | EINVAL    | claim table inconsistent (kernel bug)      |

## MkMmioMap

```
i64 MkMmioMap(
    a0 = device_id        : u64,
    a1 = claim_epoch      : u64,
    a2 = (bar_index << 32) | flags : u64,
    a3 = offset           : u64,
    a4 = length           : u64,
    a5 = out_ptr          : *mut MmioMapOut,
);
```

**Six argument words: a0..a5.** `bar_index` is packed into the upper
half of `a2` (the broker caps it at 255 anyway); `flags` occupies
the lower half. `offset` and `length` stay full-width.

Output struct (24 bytes, `repr(C)`):

```c
struct MmioMapOut {
    uint64_t user_va;
    uint64_t length;
    uint64_t grant_id;
};
```

On success the kernel returns `0` and writes the three fields at
`out_ptr`. `user_va` is page-aligned; `length` echoes the request;
`grant_id` is the handle the holder uses for `MkMmioUnmap`.

### Alignment rules

- `offset & 0xFFF == 0`
- `length & 0xFFF == 0`
- `length > 0`
- `bar.base & 0xFFF == 0` (rejected if the device exposes a
  non-page-aligned BAR)

### BAR validation

In order:

1. `flags & ~FLAGS_KNOWN == 0` (currently `FLAGS_KNOWN = 0`)
2. `length != 0`
3. offset and length are page-multiples
4. `(pid, device_id)` has an active claim
5. `claim.epoch == claim_epoch` (rejects stale grants after a claim
   round-trip)
6. device record present in broker table
7. `bar_index < bar_count`
8. `bar.kind == MMIO`
9. `bar.base` is page-aligned
10. `phys_start = bar.base + offset`, `phys_end = phys_start + length`
    do not overflow
11. `phys_end <= bar.base + bar.size`

### Output mapping properties

- `USER` page bit set (CPL=3 access)
- `READ | WRITE`
- `NO_CACHE` and `DEVICE` (PAT/PCD = uncached)
- `NX` (no-execute)
- installed in the caller's address space only; never visible from
  any other capsule

### User VA

Reserved region: `[0x0000_0080_0000_0000, 0x0000_0090_0000_0000)`
(64 GiB). A 4 KiB guard page follows every grant so an out-of-bounds
access cannot silently spill into the next grant.

### Errors

| value  | name      | meaning                                    |
|--------|-----------|--------------------------------------------|
| `-1`   | EPERM     | no current pid; caller is not the holder   |
| `-12`  | ENOMEM    | mapping failed; user VA region exhausted   |
| `-14`  | EFAULT    | `out_ptr` null or invalid; copy-out failed |
| `-19`  | ENODEV    | device record missing                      |
| `-22`  | EINVAL    | bad alignment, BAR index, BAR kind, range, |
|        |           | length, or arithmetic overflow             |
| `-95`  | ENOTSUP   | unknown bit set in `flags`                 |
| `-116` | ESTALE    | `claim_epoch` does not match current claim |

If `write_user_value` fails after the pages were installed, the
kernel rolls the grant back so a window with no userland handle
cannot leak.

## MkMmioUnmap

```
i64 MkMmioUnmap(grant_id: u64);
```

One argument word. Drops the pages and the grant record. Caller
must be the holder.

Errors:

| value  | name      | meaning                                    |
|--------|-----------|--------------------------------------------|
| `-1`   | EPERM     | not the holder                             |
| `-22`  | EINVAL    | unknown `grant_id`                         |

## Revocation

Three triggers, one rule: the grant disappears, the pages disappear
with it, and the TLB shootdown is per-asid SMP-aware.

| Trigger              | Function                          | Unmaps? | TLB              |
|----------------------|-----------------------------------|---------|------------------|
| `MkMmioUnmap`        | `mmio::release::unmap_grant`      | yes     | `flush_tlb_one_smp` per page |
| `MkDeviceRelease`    | `mmio::release::release_for_device` | yes   | `flush_tlb_one_smp` per page |
| Process exit (self)  | `release_all_for_pid(pid, true)`  | yes     | `flush_tlb_one_smp` per page |
| Process exit (cross) | `release_all_for_pid(pid, false)` | no      | AS reaper drops PTEs         |

The cross-pid exit path skips the unmap because dereferencing a
foreign address space would walk the wrong page tables. The
address-space reaper destroys the PTEs wholesale in that case. This
relies on the existing single-CPU `CURRENT_PID` invariant and is
**not SMP-complete**; once APs schedule independently the broker
must shoot grants on every CPU that may still be running the dying
capsule's CR3. Tracked separately under the SMP migration plan.

## MkIrqBind

```
i64 MkIrqBind(
    a0 = device_id    : u64,
    a1 = claim_epoch  : u64,
    a2 = irq_source   : u32,    // GSI for legacy INTx
    a3 = flags        : u32,    // currently must be zero
    a4 = out_ptr      : *mut IrqBindOut,
);
```

**Five argument words: a0..a4.** Output struct (16 bytes,
`repr(C)`):

```c
struct IrqBindOut {
    uint64_t grant_id;
    uint64_t vector;        // 8..255, opaque to userland
};
```

### IRQ mode

This slice implements **legacy INTx via the IO-APIC only.** MSI and
MSI-X are not yet wired and will be rejected — the broker requires
the device to expose a non-zero `irq_pin` and an `irq_line`
matching `irq_source`. Every grant runs:

- level-triggered or edge-triggered as the MADT ISO table reports
- delivered to the BSP only (no IRQ steering across CPUs yet)
- mapped to a vector in the reserved broker pool (`0x60..=0x6F`)
- masked at the IO-APIC immediately after every fire; the holder
  unmasks via `MkIrqAck`

GIC, PLIC, and any other non-x86 controller path is not implemented
here — the kernel does not pretend to route them.

### Validation order

1. `flags & ~FLAGS_KNOWN == 0` (currently `FLAGS_KNOWN = 0`)
2. caller has an active claim on `device_id`
3. `claim.epoch == claim_epoch`
4. device record present
5. device exposes a real INTx pin (`irq_pin != 0` and
   `irq_line != 0xFF`)
6. `irq_source == device.irq_line`
7. no other grant already binds `irq_source`
8. broker vector pool has a free slot

### Errors

| value  | name      | meaning                                    |
|--------|-----------|--------------------------------------------|
| `-1`   | EPERM     | not the holder; copy-out failed            |
| `-12`  | ENOMEM    | broker vector pool exhausted               |
| `-14`  | EFAULT    | `out_ptr` null or invalid                  |
| `-16`  | EBUSY     | another grant already binds this IRQ       |
| `-19`  | ENODEV    | device record missing; IO-APIC programming |
|        |           | failed                                     |
| `-22`  | EINVAL    | `irq_source` does not match the device's   |
|        |           | INTx line, or device has no INTx pin       |
| `-95`  | ENOTSUP   | unknown bit set in `flags`                 |
| `-116` | ESTALE    | `claim_epoch` does not match               |

### Hard-IRQ delivery rules

The kernel's per-vector ISR runs with interrupts disabled. The
dispatcher does only this work:

1. atomic load of the per-grant slot (skip + EOI if inactive)
2. mask the IO-APIC line so the device cannot re-fire
3. atomic increment of the per-grant `seq` counter; on saturation,
   bump a separate `overflow` counter
4. send LAPIC EOI

The dispatcher never allocates, never takes a sleeping or blocking
lock, and never invokes IPC, paging, or the scheduler. Notification
of the userland holder is by atomic counter only — the holder
observes the increment via `MkIrqPoll` from normal syscall context.

## MkIrqUnbind

```
i64 MkIrqUnbind(grant_id: u64);
```

One argument word. Masks the line, deactivates the slot, frees the
broker vector, drops the grant record. Errors: `EPERM` (not
holder), `EINVAL` (unknown grant id).

## MkIrqAck

```
i64 MkIrqAck(grant_id: u64);
```

One argument word. Unmasks the IO-APIC line for the grant; the
device may now re-assert. Required because the dispatcher always
masks on fire, so without an ack the line stays disabled. Errors:
same as `MkIrqUnbind`.

## MkIrqPoll

```
i64 MkIrqPoll(
    a0 = grant_id : u64,
    a1 = out_ptr  : *mut IrqPollOut,
);
```

Output struct (16 bytes, `repr(C)`):

```c
struct IrqPollOut {
    uint64_t seq;       // monotonically increasing fire count
    uint64_t overflow;  // saturation events
};
```

The holder compares `seq` to its last observation to learn how many
fires were posted. `overflow != 0` means the dispatcher saturated
(slot was masked but a re-mask attempt failed, or the 64-bit
counter wrapped — which would take longer than the heat death of
this hardware on real workloads). Errors: same as `MkIrqUnbind`.

A blocking `MkIrqWait` will land alongside the kernel's wait/wake
primitive. Until then this slice is polling-only.

## Limitations of the IRQ slice

- **Legacy INTx only.** No MSI, no MSI-X, no per-CPU steering.
- **BSP delivery only.** The IO-APIC RTE always targets the BSP.
- **16 simultaneous grants.** Broker vector pool is fixed at
  `0x60..=0x6F`.
- **Polling-only notification.** The capsule reads the counter.
  `MkIrqWait` is future work.
- **No level-triggered ack at the device.** The kernel masks the
  IO-APIC line; the device's deassertion semantics are the
  driver's responsibility.

## MkDmaMap

```
i64 MkDmaMap(
    a0 = device_id    : u64,
    a1 = claim_epoch  : u64,
    a2 = length       : u64,
    a3 = flags        : u32,
    a4 = out_ptr      : *mut DmaMapOut,
);
```

**Five argument words: a0..a4.** Output struct (32 bytes,
`repr(C)`):

```c
struct DmaMapOut {
    uint64_t user_va;
    uint64_t device_addr;
    uint64_t length;
    uint64_t grant_id;
};
```

`length` is page-multiple, `> 0`, and capped at one page in this
slice (see "Limitations" below). The broker:

1. validates the claim and epoch
2. allocates a single physical frame from the kernel frame
   allocator
3. zeroes the frame through the kernel direct map
4. reserves a 4 KiB user VA window (followed by a guard page) in
   the user DMA region
5. maps the frame into the caller's user address space with
   user / read+write / no-execute / write-back-cacheable
   attributes
6. records the grant
7. returns `(user_va, device_addr, length, grant_id)` to the caller

`device_addr` is the address the device may use in descriptor
fields. Today, on QEMU without an IOMMU, that equals the physical
address of the frame; on a future IOMMU-backed path it will be the
IOMMU-translated bus address.

### Output mapping properties

- `USER` page bit set (CPL=3 access)
- `READ | WRITE`
- `NX` (no-execute)
- write-back cacheable; coherent DMA on x86_64 PCI bus snooping
- installed in the caller's address space only

### User VA

Reserved region: `[0x0000_00A0_0000_0000, 0x0000_00B0_0000_0000)`.
Each grant gets a 4 KiB window followed by a 4 KiB guard page so an
out-of-bounds access cannot silently spill into the next grant.

### Errors

| value  | name      | meaning                                    |
|--------|-----------|--------------------------------------------|
| `-1`   | EPERM     | not the holder; copy-out failed            |
| `-12`  | ENOMEM    | frame allocator empty; user VA exhausted;  |
|        |           | mapping failed                             |
| `-14`  | EFAULT    | `out_ptr` null or invalid                  |
| `-19`  | ENODEV    | device record missing                      |
| `-22`  | EINVAL    | bad alignment or length, or length above   |
|        |           | the per-grant cap                          |
| `-95`  | ENOTSUP   | unknown bit set in `flags`                 |
| `-116` | ESTALE    | `claim_epoch` does not match               |

If `write_user_value` fails after the grant is installed, the
broker rolls the grant back so a buffer with no userland handle
cannot leak.

## MkDmaUnmap

```
i64 MkDmaUnmap(grant_id: u64);
```

One argument word. Scrubs the buffer, unmaps the user pages
(with the per-asid SMP TLB shootdown), frees the physical frame
back to the allocator, drops the grant record. Errors:

| value | name    | meaning             |
|-------|---------|---------------------|
| `-1`  | EPERM   | not the holder      |
| `-22` | EINVAL  | unknown `grant_id`  |

## Revocation (DMA)

Three triggers, one rule: the buffer is scrubbed before the frame
returns to the allocator, the user mapping is dropped, the record
disappears.

| Trigger | Function | Unmaps user pages? | Buffer scrubbed? |
|---|---|---|---|
| `MkDmaUnmap` | `dma::release::unmap_grant` | yes | yes |
| `MkDeviceRelease` | `dma::release::release_for_device` | yes | yes |
| Process exit (self) | `release_all_for_pid(pid, true)` | yes | yes |
| Process exit (cross) | `release_all_for_pid(pid, false)` | no — AS reaper drops PTEs | yes |

## Limitations of the DMA slice

- **Single-page grants only.** A driver capsule that needs more
  than 4 KiB at a time issues several grants. Multi-page contiguous
  grants need the frame allocator to grow a contiguous-run path
  and are deferred. virtio-rng's queue + buffer needs at most two
  single-page grants.
- **No IOMMU.** On QEMU without `intel-iommu`, the device sees raw
  physical addresses. A capsule could put any physical address in
  a descriptor `addr` field and the device will DMA there. This is
  a fundamental property of x86 without IOMMU enabled — the broker
  does not (and cannot) prevent it. Production on bare metal must
  enable VT-d / AMD-Vi and the broker DMA path will then use a
  per-device IOMMU domain so `device_addr` becomes a translated
  bus address; until that work lands, treat real-hw DMA as
  trust-boundary debt.
- **No bounce buffers, no scatter-gather.** A grant is one
  contiguous frame.
- **Cache management is x86-specific.** Write-back cacheable is
  correct on x86 (PCI bus snooping); aarch64 / riscv64 will need
  per-arch cache mode handling when those backends land.
