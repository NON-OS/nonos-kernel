# capsule_input_router

## Role

`capsule_input_router` drains the kernel-side MPSC input ring, routes events
to subscribers based on per-pid masks, and honours exclusive grabs. It owns
no devices: driver capsules (PS/2, USB HID, I2C HID, virtio-input) post
normalized events through `MkInputEventPost`; this router consumes them
through `MkInputEventDrain` and dispatches.

```text
driver.ps2_kbd0  --post-->\
driver.usb_hid0  --post--> [kernel input ring] --drain--> input_router
driver.i2c_hid0  --post-->/                                    |
                                                               v
                                                      focused subscriber pid
```

## Microkernel contract

The manifest grants `CoreExec`, `IPC`, `Memory`, and `Debug`:

```text
CAPSULE_REQUIRED_CAPS = 0x119
```

Both `MkInputEventDrain` (gated on `can_ipc`) and `mk_ipc_send_to_pid`
ride the `IPC` capability. The router does not need driver, IRQ, or DMA
authority.

## IPC surface

Service endpoint: `service:4320:input_router`. Reply endpoint:
`reply:4321:endpoint.input_router.reply`. Envelope follows the standard
`NIRS` 20-byte header (`MAGIC | VERSION | op | flags | _pad | request_id |
payload_len`).

| op                 | code | body                                  | reply       |
| ------------------ | ---: | ------------------------------------- | ----------- |
| `OP_HEALTHCHECK`   | 0x01 | empty                                 | status only |
| `OP_SUBSCRIBE`     | 0x02 | `kind_mask u32, _pad u32`             | status only |
| `OP_GRAB_REQUEST`  | 0x03 | `kind_mask u32, _pad u32`             | status only |
| `OP_GRAB_RELEASE`  | 0x04 | empty                                 | status only |

Delivered events ride a separate `NINP` envelope (8-byte header + 32-byte
`InputEvent`) sent via `mk_ipc_send_to_pid` to the resolved subscriber.

## Routing model

1. If a grab is held for the event's `kind`, the holder receives it
   exclusively.
2. Otherwise every subscriber whose `kind_mask` includes the event's
   `kind` bit gets a copy.

`kind` values mirror `nonos_libc::INPUT_KIND_*`. Mask bit `n` selects
`kind == n`.
