# Display and input capsules

The kernel hands two trusted streams to userland: the framebuffer
record from the boot handoff, and the raw input event stream from
the input interrupt path. Two capsules own these:

- `capsule_display` owns the framebuffer.
- `capsule_input` owns the input stream.

Every other capsule that wants to draw or read input talks to one
of these two over IPC.

## 1. Display handoff

The kernel does not draw. The boot handoff records the framebuffer
geometry and physical address. `capsule_display` is granted an
endpoint over which it receives:

```
DisplayHandoff {
    fb_phys:   u64       // physical address
    fb_size:   u64       // bytes
    width:     u32
    height:    u32
    pitch:     u32       // bytes per scanline
    format:    u32       // packed pixel format id
    cursor_y:  u32       // bottom of the boot log scrollback
}
```

The kernel maps `fb_phys..fb_phys+fb_size` into the display
capsule's address space at spawn time. No other capsule has a
direct mapping; surface presents go through the display protocol.

## 2. Display protocol

`capsule_display` exposes one endpoint:

```
endpoint:  display.surface
ABI: see abi/display_surface.proto.json
```

Operations:

| Op | Direction | Effect |
|---|---|---|
| `EnumerateModes` | client → display | returns the list of supported modes (today, the boot mode only) |
| `AllocateSurface` | client → display | returns a `surface_id` and a shared-memory region for the back buffer |
| `PresentFull` | client → display | atomically copies the back buffer into the framebuffer |
| `PresentRect` | client → display | copies a clipped region |
| `ReleaseSurface` | client → display | returns the surface to the pool |

Surfaces are owned by the requesting capsule. The display capsule
tracks ownership by caller pid and rejects any cross-pid reference.

## 3. Input handoff

The kernel owns the input interrupt vectors (PS/2, USB HID via the
hardware broker, serial debug input). The interrupt handler enqueues
raw events onto a kernel-side ring; `capsule_input` reads the ring
through one syscall:

```
MkInputDrain(buf, len) -> count
```

This call is gated by a kernel capability (`CAP_INPUT_DRAIN`)
granted only to the input capsule at spawn. No other capsule can
read the ring.

## 4. Input event ABI

```
InputEvent {
    timestamp_ns: u64       // monotonic
    device_id:    u32       // logical device, assigned by the input capsule
    kind:         u8        // KEY=1, POINTER=2, AXIS=3, TOUCH=4, GAMEPAD=5
    code:         u32       // device-specific code (HID usage)
    value:        i32       // signed value
    flags:        u32       // pressed, repeated, modifiers...
}
```

Wire format is fixed-size, big-endian, 28 bytes per event.

## 5. Input distribution

`capsule_input` normalises raw events and distributes them. Default
policy:

- keyboard events go to `capsule_compositor` (which routes them to
  the focused window)
- pointer events go to `capsule_compositor`
- touch events go to `capsule_compositor`
- gamepad events go to whichever capsule holds an active gamepad
  grant

A capsule that needs raw input (a global hotkey daemon) gets a
`global_input` grant from the user, mediated through the compositor's
"input bridge" endpoint. The kernel sees only the cap; it does not
adjudicate which event goes where.

## 6. Capabilities

Display surface use is gated by `CAP_DISPLAY`. Input event read is
gated by `CAP_INPUT`. The compositor needs both. App capsules need
`CAP_DISPLAY` only for client-side rendering; they receive input
relayed by the compositor under their own `CAP_INPUT` cap.

## 7. Failure model

- display capsule death: framebuffer freezes on the last presented
  frame; init respawns the capsule and re-establishes the surface
  pool. Apps see `ESTALE` on present until then.
- input capsule death: input stops being delivered; the kernel ring
  fills and old events drop. Init respawns the capsule and the ring
  is drained.

Neither death takes the system down, and the kernel never resumes
input or display itself.
