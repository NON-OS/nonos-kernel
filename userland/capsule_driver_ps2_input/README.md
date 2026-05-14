# capsule_driver_ps2_input

## Role

`capsule_driver_ps2_input` is the i8042 keyboard capsule. It owns brokered PIO
access to the PS/2 controller, receives keyboard interrupts, decodes scancodes,
and exposes keyboard events over IPC.

Focus, window routing, input-method policy, and lock-screen policy belong to
higher-level userland capsules, not to the kernel and not to this driver.

```text
i8042 ports -- MkPioRead/MkPioWrite --> driver.ps2_kbd0
    |
    `-- IRQ1 -- MkIrqPoll/MkIrqAck --> bounded key-event ring
                                      |
                                      `--> IPC consumers
```

## Microkernel contract

The capsule uses brokered port and interrupt authority:

- `MkDeviceList` locates the PS/2 keyboard controller record.
- `MkDeviceClaim` owns the controller claim.
- `MkPioGrant`, `MkPioRead`, and `MkPioWrite` access i8042 ports.
- `MkIrqBind`, `MkIrqPoll`, and `MkIrqAck` own keyboard interrupts.
- `MkIpcRecv` and `MkIpcSend` serve `driver.ps2_kbd0` on
  `service:4208:driver.ps2_kbd0`.

The kernel does not translate keys, route input to windows, or store user
keystrokes. It only grants PIO/IRQ and revokes them on exit.

## Interface contract

| Operation | Meaning | Reply payload |
|---|---|---|
| `OP_HEALTHCHECK` | server liveness | status word |
| `OP_POLL_EVENTS` | drain decoded keyboard events | count plus 3-byte event records |
| `OP_GET_STATE` | modifier/key state snapshot | fixed state payload |

## Authority

The manifest grants `IPC`, `Memory`, `Driver`, `DeviceEnum`, `Irq`, and `Pio`
(`CAPSULE_REQUIRED_CAPS = 0x158018`). It intentionally has no `Mmio`, `Dma`,
graphics, filesystem, network, admin, or debug authority.

```text
allowed:   i8042 PIO range, IRQ, in-memory event ring, IPC
forbidden: DMA, MMIO, focus policy, UI routing, persistent key logs
```

## Privacy and persistence

Keystrokes are private input. The capsule keeps only a bounded in-memory event
ring. It does not persist keys, write logs, expose events to unrelated
capsules, or retain state after process exit.

## Runtime lifecycle

The capsule claims i8042, grants PIO ports, binds IRQ1, drains stale output,
initializes decoder state, and serves event polling. Teardown releases IRQ,
PIO, and device claim.

## Failure model

PIO grant or IRQ bind failure aborts startup. A full event ring drops new
events deterministically rather than blocking IRQ handling. Bad scancode
sequences are contained in the decoder and do not enter kernel input policy.

## Current implemented surface

- Claims the PS/2 keyboard device record.
- Grants and uses the i8042 PIO range.
- Binds and acknowledges keyboard IRQs.
- Drains stale output before serving events.
- Decodes scancodes and tracks modifier state.
- Serves keyboard state and event polling over IPC.

## Wire format

Requests use the `NKBD` capsule header, version `1`, and the shared 20-byte
driver envelope. Replies begin with a 4-byte status word. Poll replies return a
count followed by 3-byte event records. State replies return the fixed modifier
and key-state payload.

## State ownership

The capsule owns the i8042 PIO grant, IRQ grant, scancode decoder state,
modifier state, and bounded event ring. The compositor and input router own
focus policy. The kernel owns no keystroke buffer.

## Operating rules

- Never persist keystrokes.
- Never route input to windows from this capsule.
- Keep raw PIO access behind broker wrappers.
- Overflow must be deterministic and visible to callers.

## Release target

The finished PS/2 capsule is a signed input-source service with stable
scancode decoding, bounded event delivery, IRQ loss recovery, controller
reinitialization, and explicit handoff to the userland input/compositor stack.
It remains an input source only and never decides focus, text policy, or UI
routing.

## Release evidence

Release requires QEMU scancode injection smoke, modifier-state proof, event
ring overflow behavior, teardown grant proof, and real keyboard hardware boot.

## Release checklist

- Signed manifest and kernel mirror present.
- QEMU scancode smoke passes.
- Modifier state and overflow behavior are tested.
- Teardown proof shows PIO/IRQ/device claim revocation.
- Real keyboard boot records events through userland input policy.

## Explicit non-goals today

No USB HID, mouse, layout engine, compose/input method, focus routing,
screen-lock policy, text rendering, or accessibility policy lives here.

## Verification

- Build: `make -B nonos-mk-driver-ps2-input`
- Static gate: `bash nonos-ci/run-static-checks.sh`
- Architecture check: the capsule must use broker PIO wrappers, never inline
  port assembly or kernel input paths.
- Documentation check: this README is required by CI and describes privacy and
  authority because keyboard data is sensitive.
