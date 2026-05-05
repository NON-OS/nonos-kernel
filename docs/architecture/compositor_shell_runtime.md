# Compositor and shell runtime

The desktop is two capsules that cooperate, not one program.
`capsule_compositor` owns surfaces, z-order, and damage tracking.
`capsule_shell` owns the launcher, dock, status area, and session
controls. They talk through one endpoint pair.

The kernel knows about neither.

```
+--------------------------------------------------+
|  overlay layer    permission prompts, OSD        |
+--------------------------------------------------+
|  shell layer      dock, launcher, status area    |
+--------------------------------------------------+
|  app layer        windowed app surfaces          |
+--------------------------------------------------+
|  wallpaper layer  capsule_wallpaper only         |
+--------------------------------------------------+
                  framebuffer

   per-frame loop (capsule_compositor):
       drain input  ->  route to focused surface
                    ->  walk z-order
                    ->  damage scan
                    ->  present
```

## 1. Compositor

Inputs:

- display surface protocol from `capsule_display`
- input events from `capsule_input`
- one client endpoint for app capsules (`compositor.app`)
- one client endpoint for the shell (`compositor.shell`)

State:

- a list of surfaces with `(pid, surface_id, z_order, rect, damage)`
- focus pid
- pointer position
- modifier state

Per-frame loop:

1. Drain input events from `capsule_input`.
2. Route keyboard events to the focused surface's owner pid.
3. Route pointer events to the surface under the pointer.
4. Walk the surface list bottom-up.
5. For each surface with non-empty damage, copy from the surface's
   shared back buffer into the compositor's scratch frame.
6. Hand the scratch frame to `capsule_display` via `PresentFull`
   or `PresentRect`.

The compositor never reads an app's address space. Surfaces are
shared memory regions whose mapping the display capsule allocates
and the app capsule writes into.

## 2. Compositor surface grant

A new app capsule connects to `compositor.app` and asks for a
surface. The compositor checks `CAP_DISPLAY` on the caller, asks
`capsule_display` for a shared back buffer, and returns:

```
SurfaceGrant {
    surface_id:  u64
    width:       u32
    height:      u32
    pitch:       u32
    format:      u32
    shm_handle:  u64       // opaque handle, mapped read-write in the caller
}
```

The compositor records `surface_id -> caller_pid` and refuses any
operation on that surface from a different pid. `MkExit` of the
caller automatically releases the surface (the compositor watches
liveness through `services::lifecycle`).

## 3. Shell

`capsule_shell` is a regular surface client of the compositor with
two extra grants:

- `compositor.shell` access (so it can place its launcher / dock /
  status surfaces at fixed z-order layers)
- `system_input` (so it can register global hotkeys)

The shell owns:

- the launcher: lists installed capsules from `capsule_registry` and
  asks `capsule_installer` to spawn the selected one
- the dock: window list pulled from the compositor's surface table
- the status area: clock, network indicator (from `capsule_net`,
  later), wallet indicator (`capsule_wallet`), update indicator
  (`capsule_update`)
- the session menu: lock, log out, shut down

The shell does not draw windows; it draws its own surfaces and lets
the compositor place them. Killing the shell does not kill the
compositor, and the compositor restarts the shell on death by
asking init through the lifecycle endpoint.

## 4. Z-order layers

The compositor reserves four logical layers. Each surface is
assigned to one at allocation:

| Layer | Use | Who can place |
|---|---|---|
| `wallpaper` | bottom | `capsule_wallpaper` only |
| `app` | normal | any app capsule |
| `shell` | above apps | `capsule_shell` only |
| `overlay` | system prompts | shell + permission prompts |

The kernel does not enforce these; the compositor does, by checking
caller pid against an allow list seeded at boot.

## 5. Permission prompts

When an app asks for an optional capability post-install (for
example, requesting clipboard read), the compositor draws a
permission prompt on the `overlay` layer. The user's choice is
relayed to the `capsule_installer`, which adjusts the granted cap
mask through `MkCapGrant` or `MkCapRevoke`.

## 6. Failure model

- compositor death: display freezes; init respawns compositor; app
  surfaces are re-allocated through reconnects. App capsules that
  cannot reconnect to the compositor stay alive but invisible.
- shell death: dock/launcher disappears; compositor signals init to
  respawn the shell; apps continue.
- both die: init brings up the recovery shell, which is the same
  binary as the normal shell with reduced caps.

The kernel itself does not draw a recovery overlay; recovery is
serial-only as documented in `boot_to_desktop.md`.
