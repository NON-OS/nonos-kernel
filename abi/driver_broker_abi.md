# Driver broker ABI

This file documents the kernel-side broker syscalls. The numbers
are reserved in `crate::syscall::numbers::SyscallNumber`. A syscall
is added to the active dispatch only when its kernel-side
implementation is real; the others are placeholders in the enum
for ABI stability.

ABI version: 1.

## 1. Implemented in this slice

### `MkDeviceList(class: u32, buf: *mut DeviceRecord, count: u32) -> i64`

Returns a snapshot of the broker's device table filtered by class.
Writes up to `count` records to `buf` and returns the number
written. The number written is bounded by `count` and by the
table's current size. Calling with `count == 0` and `buf == NULL`
returns the table size (probe form).

`DeviceRecord` is the fixed-size structure:

```
DeviceRecord {
    device_id:  u64       // broker-assigned, stable across boot
    bus_kind:   u8        // BUS_PCI=1, BUS_ACPI=2, BUS_VIRT=3
    class:      u32       // class id, see §4
    vendor:     u16       // vendor id (PCI) or 0 for non-PCI
    device:     u16       // device id (PCI) or 0 for non-PCI
    flags:      u32       // CLAIMED=1, DISABLED=2
    bar_count:  u8       // valid BAR slot span, not compacted count
    bars:       [Bar; 6]  // hardware BAR indices preserved; holes are zeroed
}

Bar {
    base:   u64
    size:   u64
    kind:   u8       // BAR_MMIO=1, BAR_PIO=2
    flags:  u8       // PREFETCH=1, MEM64=2
}
```

Cap-gated by `CAP_DEVICE_ENUM`. Returns `-EPERM` if the caller
lacks the cap.

## 2. Reserved for the next slice

Numbers reserved; not yet routed to a real implementation. A call
to one of these returns `-ENOSYS` today.

```
MkDeviceClaim(device_id: u64, manifest_hash: *const [u8; 32]) -> i64
MkDeviceRelease(device_id: u64) -> i64
MkMmioMap(device_id: u64, bar_index: u8, offset: u64, len: u64) -> i64
MkPioGrant(device_id: u64, port_base: u16, port_count: u16) -> i64
MkIrqBind(device_id: u64, irq_pin: u8) -> i64
MkDmaMap(device_id: u64, len: u64, flags: u32, bus_addr_out: *mut u64) -> i64
MkDmaUnmap(device_id: u64, handle: u64) -> i64
```

## 3. Errors

| Code | Meaning |
|---|---|
| `-EPERM` | caller lacks the required cap |
| `-EINVAL` | argument out of range, alignment violated, or unknown class |
| `-ENODEV` | `device_id` not in the broker table |
| `-EBUSY` | device already claimed by a different pid |
| `-EFAULT` | user pointer not mapped or not writable |
| `-ENOMEM` | broker table full or DMA bounce pool exhausted |
| `-ESTALE` | claim epoch advanced; the device was released and re-claimed |
| `-ENOSYS` | reserved syscall, not yet implemented |

## 4. Class IDs

```
CLASS_RNG       = 0x0001
CLASS_BLOCK     = 0x0010
CLASS_NETWORK   = 0x0020
CLASS_DISPLAY   = 0x0030
CLASS_INPUT     = 0x0040
CLASS_AUDIO     = 0x0050
CLASS_SERIAL    = 0x0060
CLASS_USB_HOST  = 0x0070
CLASS_OTHER     = 0xFFFF
```

The broker classifies devices using PCI class codes on PCI buses
and a fixed table for ACPI/virt buses. A device whose class is
not recognised reports `CLASS_OTHER`.

## 5. Stability

ABI v1 freezes the layout of `DeviceRecord` and the syscall
numbers above. Field additions inside `DeviceRecord` require a
new record kind and a separate syscall (`MkDeviceListV2`); the
broker will not silently extend the v1 record.
