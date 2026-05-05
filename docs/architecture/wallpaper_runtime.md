# Wallpaper runtime

`capsule_wallpaper` paints the bottom layer of the compositor. It is
a normal userland capsule with one privilege: it is the only client
allowed to allocate a surface on the compositor's `wallpaper` z-order
layer.

```
   capsule_wallpaper                compositor
   -----------------                ----------
        |                                |
        |  open(layer=wallpaper)         |
        |------------------------------->|
        |                                |  pid in allow list?
        |                                |  layer free?
        |       SurfaceGrant(buf, w, h)  |
        |<-------------------------------|
        |                                |
        |  draw frame -> shared buffer   |
        |  commit(seq)                   |
        |------------------------------->|
        |                                |  composite:
        |                                |    [wallpaper]   <-- this surface
        |                                |    [windows...]
        |                                |    [overlays]
        |                                |    [cursor]
        |                                |
        |  (wallpaper crash)             |
        |   X                            |
        |   X                            |  surface goes inactive
        |                                |  -> clear to fallback color
        |                                |  init respawns capsule
```

## 1. Surface model

At startup, `capsule_wallpaper` opens a connection to the compositor
and requests a `wallpaper` layer surface sized to the current display
mode. The compositor verifies the caller pid against the boot-time
allow list and returns a surface grant.

The wallpaper surface is opaque. The compositor draws everything
above it. Apps cannot read this surface; the shared memory region
is mapped read-write only in the wallpaper capsule.

## 2. Wallpaper sources

A wallpaper source is one of:

- `static_image`: PNG or JPEG decoded once into the back buffer
- `slideshow`: a list of static images, switched on a timer
- `solid_color`: ARGB fill
- `generative`: a tiny rendering routine that emits frames over time

The first three are the common case. Generative wallpapers are
sandboxed inside `capsule_wallpaper`; they are not separate capsules
and they cannot reach beyond what `capsule_wallpaper` itself can
reach.

## 3. Wallpaper frame ABI

Internal to `capsule_wallpaper`, but documented because third-party
generative wallpapers ship as `.wpgen` files the capsule loads:

```
WallpaperFrame {
    width:        u32
    height:       u32
    pitch:        u32
    format:       u32       // packed pixel format id
    timestamp_ns: u64       // monotonic, frame production time
    pixels:       [u8; pitch * height]
}
```

`.wpgen` is a content-addressed bundle: a manifest (subset of the
capsule manifest, minus payment fields) plus an ELF that exports
one symbol, `wpgen_render(width, height, t_ns, out: *mut u8) -> i32`.
The capsule sandboxes execution by running the renderer in a thread
with no IPC caps; the only output is the back buffer.

## 4. Persistence

By default the wallpaper choice is RAM-only. On reboot the user gets
the OS default wallpaper. Persisting the wallpaper choice requires
`CAP_PERSISTENCE` on `capsule_wallpaper` (set in its manifest as
optional). The capsule writes its config through `capsule_registry`
the same way other persistent capsules do.

## 5. Performance budget

`capsule_wallpaper` runs at low priority. The compositor presents
it with a minimum frame interval (15 fps for generative, lower for
static) and skips frames if the system is under load. The wallpaper
never starves an app capsule.

## 6. Crash behaviour

Wallpaper crash: the compositor sees the surface go inactive and
clears the wallpaper layer to a configured fallback solid color. Init
respawns the wallpaper capsule on its next supervisor tick. The user
sees a single-color desktop briefly.

## 7. What the wallpaper capsule cannot do

- read any other surface
- read input events (no `CAP_INPUT`)
- read or write the filesystem (no `CAP_VFS`) unless the user
  explicitly granted it for slideshow file access
- reach the network (no `CAP_NETWORK`)
- talk to the wallet (no wallet caps)
- persist anything outside its registry-managed config

The wallpaper surface is a passive paint job; that is the only thing
this capsule does.
