# capsule_driver_xhci

## Role

`capsule_driver_xhci` is the USB 3 host-controller capsule. It owns xHCI
controller bring-up, controller rings, event processing, and port status. USB
class policy belongs to separate HID, storage, audio, network, and hub
capsules above it.

```text
USB class capsules
    |
    | controller service IPC
    v
driver.xhci0 -- MMIO / IRQ / DMA broker grants --> xHCI controller
    |
    +-- command ring
    `-- event ring / ERST
```

## Microkernel contract

The capsule interacts with hardware only through broker grants:

- `MkDeviceList` locates the xHCI controller.
- `MkDeviceClaim` owns the controller claim.
- `MkMmioMap` maps the controller register window.
- `MkIrqBind`, `MkIrqPoll`, and `MkIrqAck` own controller interrupts.
- `MkDmaMap` and `MkDmaUnmap` allocate DCBAA, scratchpads, command ring,
  event ring, and ERST storage.
- `MkIpcRecv` and `MkIpcSend` serve `driver.xhci0` on
  `service:4206:driver.xhci0`.

The kernel does not enumerate USB devices, parse descriptors, or implement USB
class behavior. It grants resources and revokes them.

## Interface contract

| Operation | Meaning | Reply payload |
|---|---|---|
| `OP_HEALTHCHECK` | server liveness | status word |
| `OP_CONTROLLER_STATUS` | controller register/ring state | 52-byte status |
| `OP_PORT_STATUS` | port state list | count plus 8-byte entries |

## Authority

The manifest grants `IPC`, `Memory`, `Driver`, `DeviceEnum`, `Mmio`, `Irq`,
and `Dma` (`CAPSULE_REQUIRED_CAPS = 0xF8018`). It has no filesystem, input
routing, audio, network, graphics, admin, or debug authority.

```text
allowed:   xHCI claim, MMIO, IRQ, controller DMA rings, controller IPC
forbidden: HID policy, mass-storage policy, CDC network policy, kernel USB
```

## Privacy and persistence

Controller rings and descriptors are runtime-only DMA state. The capsule does
not persist USB topology, device descriptors, keystrokes, storage payloads, or
audio data. Class capsules must request only the information they are
authorized to consume.

## Runtime lifecycle

The capsule claims xHCI, maps MMIO, binds IRQ, allocates controller DMA state,
halts and resets the controller, starts command/event rings, runs a No-op
command, and serves controller status IPC. Teardown releases DMA, IRQ, MMIO,
and claim grants.

## Failure model

Setup failure rolls back every prior grant. Controller-not-ready and command
timeout paths abort promotion. Device class requests are rejected until
enumeration and endpoint-zero transfer handling are implemented.

## Current implemented surface

- Claims the xHCI controller.
- Maps MMIO and binds IRQ.
- Allocates DCBAA, scratchpads, command ring, event ring, and ERST.
- Halts and resets the controller.
- Waits for CNR clear and starts the controller.
- Issues a No-op command.
- Serves controller and port status over IPC.

## Wire format

Requests use the `NXHC` capsule header, version `1`, and the shared 20-byte
driver envelope. Replies begin with a 4-byte status word. Controller status
returns 52 bytes. Port status returns a count plus 8-byte port records.

## State ownership

The capsule owns MMIO mapping, IRQ grant, DCBAA, scratchpads, command ring,
event ring, ERST, port state snapshot, and controller command state. USB class
capsules own device-class policy.

## Operating rules

- Do not expose class-device APIs before endpoint-zero transfers exist.
- Keep descriptor parsing out of the kernel.
- Bound controller-reported port lists.
- Roll back DMA, IRQ, MMIO, and claim grants on setup failure.

## Release target

The finished xHCI capsule is a signed USB host-controller service with slot
enable, address-device, endpoint-zero control transfers, event processing,
port-change handling, reset recovery, and class-capsule handoff. It owns the
controller mechanics only; HID, storage, audio, CDC, and hub policy stay in
separate USB class capsules.

## Release evidence

Release requires QEMU `qemu-xhci` smoke, No-op completion proof, port-change
proof, endpoint-zero GetDescriptor smoke, teardown DMA revocation, and class
capsule handoff tests.

## Release checklist

- Signed manifest and kernel mirror present.
- QEMU xHCI No-op smoke passes.
- Port-change and GetDescriptor smoke pass.
- Teardown proof shows DMA/IRQ/MMIO/device claim revocation.
- HID or mass-storage class capsule handoff is proven over IPC.

## Explicit non-goals today

No device addressing, endpoint-zero transfer service, hub policy, HID, USB
mass storage, USB audio, CDC Ethernet, isochronous scheduling, or persistent
USB inventory lives here.

## Verification

- Build: `make -B nonos-mk-driver-xhci`
- Static gate: `bash nonos-ci/run-static-checks.sh`
- Architecture check: xHCI must remain MMIO/IRQ/DMA broker-only and must not
  use raw PIO or kernel USB internals.
- Documentation check: this README is required by the driver docs gate.
