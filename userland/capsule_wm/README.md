# capsule_wm

## Role

`capsule_wm` owns window state for every running capsule on the desktop:
geometry, kind (normal / dialog / tooltip / popup), visibility, z-order,
focus, and lifecycle subscriptions. It does **not** own pixels. Apps register
their surface with the kernel registry, share the handle with the compositor
directly, and tell the wm only their (window_id, geometry, kind) so the wm can
answer authoritative questions like "which window owns the point under the
cursor".

```text
app   --SCENE_SUBMIT(handle, rect)-->  compositor
  \                                         ^
   \--OP_WINDOW_OPEN/MOVE/RESIZE-->  wm  --OP_FOCUS_SET-->/
                                          --OP_LIFECYCLE notify subscribers
```

## Microkernel contract

The manifest grants `CoreExec`, `IPC`, `Memory`, and `Debug`:

```text
CAPSULE_REQUIRED_CAPS = 0x119
```

No driver, IRQ, or DMA authority. Every interaction with peer capsules
rides `mk_ipc_call` and `mk_ipc_send_to_pid` over the standard `NWMP`
envelope.

## IPC surface

Service endpoint: `service:4330:wm`. Reply endpoint: `reply:4331:endpoint.wm.reply`.

| op                     | code | body                                              |
| ---------------------- | ---: | ------------------------------------------------- |
| `OP_HEALTHCHECK`       | 0x01 | empty                                             |
| `OP_WINDOW_OPEN`       | 0x02 | `window_id u32, kind u32, x u32, y u32, w u32, h u32` |
| `OP_WINDOW_CLOSE`      | 0x03 | `window_id u32, _pad u32`                          |
| `OP_WINDOW_MOVE`       | 0x04 | `window_id u32, _pad u32, x u32, y u32`             |
| `OP_WINDOW_RESIZE`     | 0x05 | `window_id u32, _pad u32, w u32, h u32`             |
| `OP_WINDOW_FOCUS`      | 0x06 | `window_id u32, _pad u32`                          |
| `OP_WINDOW_RAISE`      | 0x07 | `window_id u32, _pad u32`                          |
| `OP_LIFECYCLE_SUBSCRIBE` | 0x08 | empty                                           |

`window_id` is per-pid; the wm keys the table by `(owner_pid, window_id)`.

## Notifications

Lifecycle subscribers receive an `NWMV` envelope (8-byte header +
20-byte payload: `event_kind u32, owner_pid u32, window_id u32, x u32, y u32`)
on `OP_WINDOW_OPEN` and `OP_WINDOW_CLOSE`. Event kinds: 0 = opened, 1 = closed.
