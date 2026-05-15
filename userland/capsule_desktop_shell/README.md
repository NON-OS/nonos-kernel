# capsule_desktop_shell

Owns the desktop chrome: top menubar, left-side dock, bottom dock,
tray, spotlight, notification feed. The shell allocates one full-screen
overlay surface, paints the chrome regions, registers the buffer with
the kernel surface registry, and hands the handle to the compositor at
z=1 (just above the wallpaper).

```
shell  ── mk_surface_register / mk_surface_share ──> kernel registry
       ── compositor::OP_SCENE_SUBMIT(handle, full screen, z=1)
       ── compositor::OP_DAMAGE_COMMIT(rect)   on tray / notify / spotlight changes
       ── wallpaper::OP_SET_WALLPAPER(argb)    when the user picks a colour
```

Required caps: `CoreExec | IPC | Memory | Debug | GraphicsSurfaceCreate
| GraphicsDisplayQuery = 0x1919`.

## Wire

Service `service:4410:desktop_shell`. Envelope `NDSH` (4-byte magic,
2-byte version, 2-byte op, 2-byte flags, 2-byte _pad, 4-byte request
id, 4-byte payload len; 20 bytes total).

| op              | code | body                                            |
| --------------- | ---: | ----------------------------------------------- |
| HEALTHCHECK     | 0x01 | empty                                           |
| TRAY_REGISTER   | 0x02 | `tray_id u32, label_len u32, label_bytes[24]`   |
| TRAY_UPDATE     | 0x03 | `tray_id u32, label_len u32, label_bytes[24]`   |
| TRAY_REMOVE     | 0x04 | `tray_id u32, _pad u32`                         |
| NOTIFY          | 0x05 | `level u32, body_len u32, body_bytes[128]`      |
| SPOTLIGHT_OPEN  | 0x06 | empty                                           |

Tray slots are keyed by `(owner_pid, tray_id)`; the shell rejects a
register call when the slot is already in use. Notifications enqueue
on a bounded ring (oldest dropped on overflow) and render in the top
right of the menubar.
