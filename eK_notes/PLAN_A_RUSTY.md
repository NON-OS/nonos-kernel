# Plan A: Rusty (user surface)

Track A is the user-surface stream. Toolkit library, wallpaper, clipboard, login, desktop shell, app capsules wave 1. All CPL=3 capsule code, Mk* IPC, signed manifests. No kernel changes on this track. The kernel surface and the four substrate capsules (compositor, wm, input_router, gfx driver) are eK's deliverables in Plan B; this track consumes their op surface, never their memory.

## Operating rules (binding)

- Every capsule has the modular shape: `protocol/`, `state/`, `setup/`, `server/{parse_req,respond,runner,handlers/*}`, `main.rs`. mod.rs is decls + re-exports only. Every file ≤100 lines unless it carries a single cohesive state machine.
- Every capsule builds for `x86_64-nonos-user`, `aarch64-nonos-user`, `riscv64-nonos-user` from the first commit.
- No `static mut`. No `unsafe` except `_start`, `core::ptr::write_volatile` on pixel buffers, and the libc `mk_*` FFI.
- No cross-capsule pointers. Cross-capsule state is `(pid, handle)` pairs through the kernel surface registry only.
- Every `mk_ipc_call` carries a timeout. Default 100 ms, configurable per-op in `abi/wire.toml`.
- Every capsule has a signed NONOS-ID cert + CapsuleManifest v3 under the trust ceremony. Caps: `IPC | Memory` for everything below; no driver caps anywhere on this track.
- Toolkit is a `lib`, not a binary. It opens no IPC port. Apps link against it.
- Every server runner replies `E_BAD_OP` on unknown ops, `E_BAD_LEN` on short bodies, `E_BAD_MAGIC` on wrong magic, `E_BAD_VERSION` on version mismatch.
- Unknown surfaces, unknown windows, unknown tray ids: explicit errno, not a panic, not a silent drop.

## Shared interfaces (frozen by both devs together before any code)

Plan A only depends on these contracts from Plan B:
- compositor service name `compositor`, op surface in `abi/wire.toml`: HEALTHCHECK, SCENE_SUBMIT, SCENE_REMOVE, CURSOR_UPDATE, FOCUS_SET, INPUT_SUBSCRIBE.
- wm service name `wm`, op surface: HEALTHCHECK, WINDOW_OPEN, WINDOW_CLOSE, WINDOW_MOVE, WINDOW_RESIZE, WINDOW_FOCUS, WINDOW_RAISE, LIFECYCLE_SUBSCRIBE.
- kernel syscall set MkSurfaceRegister, MkSurfaceShare, MkSurfaceAttach, MkSurfaceRelease, MkDisplayVsyncWait. Plan A uses Share + Attach + Release; the others are eK's.

Plan A produces these contracts that Plan B consumes:
- toolkit lib API surface (`toolkit::{font, design, components, animation, image, qr}`).
- `desktop_shell` op surface: HEALTHCHECK, TRAY_REGISTER, TRAY_UPDATE, TRAY_REMOVE, NOTIFY, SPOTLIGHT_OPEN.
- `wallpaper` op surface: HEALTHCHECK, SET_WALLPAPER, GET_WALLPAPER, SET_POLICY, FADE.

## Deliverables in order

### A1. Toolkit library

`userland/toolkit/`, crate type `lib`. Port from legacy `src/graphics/{font,design_system,components,animation,image,qrcode}`. Every legacy file with `static mut` or direct framebuffer access becomes a function that takes a caller-owned `(buf: &mut [u32], stride: usize, w: u32, h: u32)`. No global state.

Layout:
```
userland/toolkit/
  Cargo.toml
  src/
    lib.rs                                  -- decls + re-exports only
    font/{atlas,glyph,render,mod}.rs
    design/{color,typography,spacing,shadow,border,mod}.rs
    components/{button,label,input,slider,list,dropdown,
                checkbox,radio,toggle,card,badge,
                colorpicker,datepicker,glass_panel,
                scroll,progress,menu,tooltip,
                tabbar,statusbar,mod}.rs
    animation/{easing,runner,timing,transitions,state,mod}.rs
    image/{png,bmp,lz4_raw,jpeg,types,mod}.rs
    qr/{ecc,mask,place,format,render,mod}.rs
```

Per-file size cap of 100 lines applies. PNG decoder needs ~6 files (decoder, deflate, huffman, inflate, scanline, mod).

Acceptance: builds with zero warnings on all three triples; static gate added that toolkit imports no kernel modules and no IPC syscalls.

### A2. capsule_image_codec

Thin IPC server wrapping `toolkit::image`. Lets non-toolkit callers (browser, plugins later) decode images without linking the toolkit.

Layout: standard capsule shape. Ops: HEALTHCHECK, DECODE_PNG, DECODE_BMP, DECODE_LZ4_RAW, DECODE_JPEG. Response: surface handle to a freshly registered ARGB8888 surface.

Caps: IPC + Memory.

### A3. capsule_wallpaper

Replace the current 96-line proof. Reads policy from `desktop_shell`, decodes a configured image via `toolkit::image` (or via `capsule_image_codec` for hot reload), allocates a full-screen surface through `MkSurfaceRegister`, submits to `compositor` as the bottom layer.

Layout:
```
src/
  protocol/...
  state/{global,lease,mod}.rs       -- current wallpaper id, decoded surface, policy
  setup/{discover,run,mod}.rs       -- mk_service_lookup(desktop_shell, compositor)
  server/handlers/{health,set_wallpaper,get_wallpaper,
                   set_policy,fade,mod}.rs
  decode_client/{wire,header,seq,mod}.rs   -- talks to image_codec
  compositor_client/{wire,header,seq,
                     scene_submit,mod}.rs
  main.rs
```

### A4. capsule_clipboard

Port legacy `graphics/clipboard/{data, history}`. Pure-userland: stores byte buffers indexed by content type.

Ops: HEALTHCHECK, COPY, PASTE, HISTORY_LIST, HISTORY_GET, CLEAR.

State: bounded ring (history depth from CapsuleManifest config, default 16 entries; total bytes cap default 256 KB).

### A5. capsule_login

Pre-desktop gate. Reads credentials from user input, validates against `capsule_keyring`. On success, signals desktop_shell to bring up the session.

Ops: HEALTHCHECK, START_SESSION, END_SESSION, GET_STATE.

State: current session pid, lock state.

Uses toolkit for the login UI. Renders into a full-screen surface, submits to compositor.

### A6. capsule_desktop_shell

The bulk port. Replace the current 77-line proof. Port from legacy `src/graphics/desktop/{dock, menubar, sidebar, status, tray, grid, logo}` + `src/graphics/spotlight/`.

Layout:
```
src/
  protocol/...
  dock/{state,render,magnify,launch,mod}.rs
  menubar/{state,clock,system_menu,render,mod}.rs
  sidebar/{state,items,utils,render,mod}.rs
  tray/{state,items,registry,render,mod}.rs
  status/{state,indicators,render,mod}.rs
  spotlight/{state,query,results,input,render,mod}.rs
  icons/{apps,system,desktop,mod}.rs
  policy/{wallpaper,dock,menubar,sidebar,tray,
          spotlight,mod}.rs
  compositor_client/{wire,header,seq,
                     scene_submit,scene_remove,
                     cursor_update,focus_set,mod}.rs
  wm_client/{wire,header,seq,
             window_open,window_focus,mod}.rs
  market_client/...                          -- lists installable apps
  wallpaper_client/...                       -- pushes wallpaper policy
  state/{global,subscriptions,mod}.rs
  setup/{discover,run,mod}.rs
  server/handlers/{health,tray_register,tray_update,
                   tray_remove,notify,
                   spotlight_open,mod}.rs
  main.rs
```

Subsystems (dock, menubar, sidebar, tray, status, spotlight) each own their own surface; compositor sees them as flat layers.

### A7. App capsules wave 1

Seven apps, each a separate capsule with the standard modular shape:

| Capsule | Legacy source |
|---|---|
| `capsule_about` | `graphics/window/apps/about/` |
| `capsule_calculator` | `graphics/window/calculator/` |
| `capsule_terminal` | `graphics/window/terminal/` |
| `capsule_file_manager` | `graphics/window/file_manager/` (uses capsule_vfs) |
| `capsule_text_editor` | `graphics/window/text_editor/` |
| `capsule_settings` | `graphics/window/settings/` (talks to desktop_shell + keyring) |
| `capsule_process_manager` | `graphics/window/process_manager/` |

Each app's main loop:
1. `mk_service_lookup("wm")`, `mk_service_lookup("compositor")`, `mk_service_lookup("input.router")`.
2. `OP_WINDOW_OPEN` against wm → window_id.
3. `OP_INPUT_SUBSCRIBE` against compositor for the matching layer.
4. Loop: `mk_ipc_recv_from` input events from compositor, update app state, render with toolkit into a surface, `OP_SCENE_SUBMIT` to compositor with damage rect, repeat.

`capsule_process_manager` needs a debug-gated kernel observability op; spec is in `abi/wire.toml` (eK adds the syscall, you call it).

## Build evidence per capsule

Each deliverable produces:
1. `make -B nonos-mk-<slug>` builds with zero warnings, three triples.
2. `make nonos-mk-<slug>-sign` produces cert + manifest.
3. Row in `docs/production-roadmap/capsule_integration_matrix.md`.
4. README contract section in the capsule's own README.
5. New gate in `nonos-ci/run-static-checks.sh` pinning the new architectural rule.
6. Boot integration: `init/entry.rs` cfg-gated spawn call + spawn shim, ordered after the substrate capsules.
7. QEMU serial trace shows the capsule joining the chain and answering at least `OP_HEALTHCHECK` from a probe driver.

## Multi-CPU + multi-arch rules (apply to every Plan A capsule)

- No capsule pins itself to a specific CPU on this track. Plan A capsules are scheduler-default.
- No `cfg(target_arch = "...")` in capsule source. Anything CPU-specific is the kernel's problem.
- Surface buffers are ARGB8888 little-endian on every arch. No byte-swap shims.
- Atomic types only. No raw memory ordering tricks; default to `Ordering::Relaxed` for counters, `Ordering::Acquire/Release` for ports, `Ordering::SeqCst` only when the comment justifies it.

## What you do not own on this track

- The kernel surface registry implementation (eK).
- Compositor, wm, input_router, virtio_gpu driver (eK).
- The eight kernel syscalls themselves (eK writes; you call them).
- vsync timing (eK; compositor does this for you).
- GPU memory allocation strategy (eK).

You can build every Plan A deliverable against the contracts in `abi/wire.toml` before eK's substrate is up. Tests are stubbed with a local mock until S2; after S2, real integration.

## Order of attack

1. Toolkit (font + design + image first slice). Unblocks every later deliverable.
2. capsule_image_codec.
3. capsule_wallpaper (real).
4. capsule_clipboard (small, fast win).
5. capsule_login.
6. capsule_desktop_shell.
7. App wave 1 in parallel where possible (about + calculator first; terminal and file_manager carry more state).

## Don't do

- Don't add a kernel module.
- Don't introduce a new IPC primitive. Mk* is enough.
- Don't read `crate::network::*`, `crate::graphics::*`, or `crate::input::*`. Those are kernel-side dead trees, not your concern.
- Don't add `#[allow(dead_code)]` or `#[allow(unused)]` anywhere. Fix by narrowing or completing.
- Don't ship a docs/ file with the same content as a README. Capsule contract goes in the capsule's README only.
