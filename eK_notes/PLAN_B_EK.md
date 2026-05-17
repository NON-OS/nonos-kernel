# Plan B: eK (graphics substrate)

Track B is the substrate stream. The four capsules that sit between the kernel and Rusty's user surface, plus the eight kernel syscalls they depend on. All capsule code is CPL=3; the eight syscall handlers are CPL=0 but bounded, frozen, and reviewed line by line. This is the harder track because it owns the novel architecture (scene graph, damage tracking, frame pacing, GPU command submission, cross-AS surface registry, multi-CPU concurrency).

## Operating rules (binding)

- Every capsule has the modular shape: `protocol/`, `state/`, `setup/`, `server/{parse_req,respond,runner,handlers/*}`, `main.rs`. mod.rs is decls + re-exports only. Every file ≤100 lines unless it carries a single cohesive state machine.
- Every capsule builds for `x86_64-nonos-user`, `aarch64-nonos-user`, `riscv64-nonos-user`.
- No `static mut`. No `unsafe` except `_start`, `core::ptr::write_volatile` on pixel buffers, MMIO volatile reads/writes inside the gfx driver, and the libc `mk_*` FFI.
- No cross-capsule pointers. Cross-capsule state is `(pid, handle)` through the kernel surface registry only.
- Every `mk_ipc_call` carries a timeout (default 100 ms, configurable per-op).
- Every capsule has a signed NONOS-ID cert + CapsuleManifest v3.
- Multi-CPU: compositor pins workers to specific CPUs by manifest declaration. Lock-free where possible; bounded critical sections elsewhere.
- Multi-arch: kernel additions go through `arch::Arch`. No `cfg(target_arch)` outside `src/arch/`.

## Shared interfaces (frozen with Rusty before any code)

Plan B produces:
- The eight kernel syscalls in `abi/wire.toml` (MkSurfaceRegister, MkSurfaceShare, MkSurfaceAttach, MkSurfaceRelease, MkSurfacePresent, MkDisplayVsyncWait, MkInputEventPost, MkInputEventDrain).
- compositor op surface: HEALTHCHECK, SCENE_SUBMIT, SCENE_REMOVE, CURSOR_UPDATE, FOCUS_SET, INPUT_SUBSCRIBE.
- wm op surface: HEALTHCHECK, WINDOW_OPEN, WINDOW_CLOSE, WINDOW_MOVE, WINDOW_RESIZE, WINDOW_FOCUS, WINDOW_RAISE, LIFECYCLE_SUBSCRIBE.
- virtio_gpu driver op surface: HEALTHCHECK, QUERY_CAPS, CREATE_RESOURCE, ATTACH_BACKING, TRANSFER_TO_HOST, SET_SCANOUT, FLUSH, CURSOR_UPDATE, VBLANK_SUBSCRIBE, MODE_LIST, MODE_SET.

Plan B consumes from Rusty:
- toolkit::font for the cursor + bring-up text rendering.
- toolkit::image for the boot logo decode.
- desktop_shell op surface (only after S5).
- wallpaper op surface (informational; compositor doesn't call it).

## Deliverables in order

### B1. Kernel syscalls + surface registry

Eight new syscalls under `src/syscall/dispatch/router/`. New file `surface_registry.rs` under `src/kernel_core/` carrying the registry table, refcount, share/attach machinery, and the per-display vsync timer.

Files (kernel-side, target ~600 LOC total):
```
src/kernel_core/surface_registry/
  mod.rs (decls + re-exports)
  table.rs                       -- (pid, sid) → SurfaceDescriptor with refcount
  share.rs                       -- handle issuance + import
  release.rs                     -- refcount decrement + free
  vsync.rs                       -- per-display deadline timer
  input_ring.rs                  -- MPSC kernel input ring for MkInputEvent*
src/syscall/dispatch/router/
  surface_ops.rs                 -- handlers for MkSurface* + MkDisplayVsyncWait
  input_ops.rs                   -- handlers for MkInputEvent*
```

Wire layout for SurfaceDescriptor and InputEvent goes in `abi/wire.toml`. Generators regenerate the userland constants.

Acceptance:
- `cargo check --features microkernel-core` passes.
- `make nonos-mk-core` builds.
- New static gate: surface registry mutation outside the registry module fails.
- The eight syscalls return well-defined errno on every error path; no panic, no kernel BUG.

### B2. capsule_driver_virtio_gpu

Modular driver capsule. Same broker grant set as `driver.virtio_net0`: IPC + Memory + Driver + DeviceEnum + Mmio + Irq + Dma. Registers `gfx.primary`.

Layout:
```
src/
  protocol/{wire,header,ops,errno,limits,endpoint,mod}.rs
  state/{global,resources,scanouts,fences,mod}.rs
  device/
    mmio/{config,control_queue,cursor_queue,mod}.rs
    virtqueue/{ring,desc,used,avail,mod}.rs
    fence/{counter,wait,mod}.rs
    irq/{handler,vblank,mod}.rs
    mod.rs
  setup/
    discover/{pci_probe,mod}.rs              -- finds VIRTIO_GPU through broker
    claim/{device,mmio,irq,dma,mod}.rs       -- broker grant sequence
    bringup/{reset,negotiate,setup_queues,
             attach_display,mod}.rs
    mod.rs
  server/parse_req.rs
  server/respond.rs
  server/runner.rs
  server/mod.rs
  server/handlers/
    health.rs query_caps.rs create_resource.rs
    attach_backing.rs transfer_to_host.rs
    set_scanout.rs flush.rs cursor_update.rs
    mode_list.rs mode_set.rs
    vblank_subscribe.rs
    mod.rs
  main.rs
```

Wire conventions follow the same NL2/NIP4 envelope shape: 4-byte magic + 2-byte version + 2-byte op + 2-byte errno + 2-byte _reserved + 4-byte request_id + 4-byte payload_len, then body.

Acceptance:
- Builds clean, three triples.
- Manifest signed.
- Boot trace shows `[gfx.virtio_gpu0] device claimed, scanout 1920x1080 ARGB8888 active`.
- compositor stub can `OP_HEALTHCHECK` it and get `E_OK`.

### B3. capsule_compositor

The architectural heart. Replace the current 95-line proof.

Layout:
```
src/
  protocol/...
  scene/
    graph/{node,layer_list,snapshot,mod}.rs   -- sequence-locked scene
    node/{transform,opacity,handle,mod}.rs
    snapshot/{builder,reader,mod}.rs          -- producer + N consumers
    mod.rs
  damage/
    rect/{ops,intersect,mod}.rs
    union/{accumulate,flush,mod}.rs
    tile/{grid,work_queue,mod}.rs             -- per-tile work distribution
    mod.rs
  cursor/
    state/{pos,visible,surface,mod}.rs
    composite/{overlay,hardware_plane,mod}.rs
    save_under/{capture,restore,mod}.rs
    mod.rs
  frame_pacer/
    loop/{tick,present_submit,mod.rs}         -- pinned CPU 0
    vsync/{wait,timestamp,mod}.rs
    deadline/{ns_to_next,catchup,mod}.rs
    mod.rs
  gfx_client/
    wire.rs header.rs seq.rs
    create_resource.rs attach_backing.rs
    transfer_to_host.rs set_scanout.rs
    flush.rs cursor_update.rs vblank.rs
    mod.rs                                    -- talks to gfx.primary
  sw_blitter/
    copy_rect/{slow,fast,mod}.rs              -- fallback path
    mod.rs
  input_router_client/{wire,header,seq,mod}.rs
  wm_client/{wire,header,seq,focus_query,mod}.rs
  state/
    global.rs
    layer_table/{insert,remove,lookup,mod}.rs
    focus.rs
    subscriptions/{register,fire,mod}.rs
    workers/{count,pinning,mod}.rs
    mod.rs
  setup/
    discover/{gfx,input_router,wm,mod}.rs
    workers/{spawn,pin_to_cpu,mod}.rs
    mod.rs
  server/parse_req.rs server/respond.rs
  server/runner.rs server/mod.rs
  server/handlers/{health,scene_submit,
                   scene_remove,cursor_update,
                   focus_set,input_subscribe,mod}.rs
  main.rs
```

Critical correctness: scene graph mutation is owned by the scene worker thread. Render workers consume immutable snapshots under a sequence lock. The frame pacer reads a snapshot, blits it (sw or gpu), then signals release. Same pattern Wayland compositors use; do not reinvent.

Multi-CPU pinning:
- scene worker: CPU 0
- render workers: CPU 1..N-1
- frame pacer (present submit): CPU 0
- gfx_client IPC thread: CPU 0

Manifest declares CPU pinning hints; if the scheduler can't honor them, compositor still runs but logs a warning at boot.

Acceptance:
- Builds clean.
- Manifest signed.
- Boot trace: `[compositor] vsync 60.0 Hz attached, N render workers on CPUs 1..N-1`.
- A wallpaper PNG composites through it with damage tracking proved on serial (`damage=full` first frame, `damage=128x64@0,0` after a cursor move).

### B4. capsule_input_router

Drains driver capsules; normalizes; routes.

Layout:
```
src/
  protocol/...
  sources/
    ps2_kbd/{wire,header,seq,poll,mod}.rs
    ps2_aux/{wire,header,seq,poll,mod}.rs
    usb_hid/{wire,header,seq,poll,mod}.rs
    i2c_hid/{wire,header,seq,poll,mod}.rs        -- stub until i2c_hid driver lands
    mod.rs
  normalize/
    kbd_event/{scancode,modifier,key_event,mod}.rs
    pointer_event/{rel,abs,wheel,button,mod}.rs
    touch_event/{contact,gesture,mod}.rs          -- stub for now
    mod.rs
  route/
    dispatch/{by_focus,by_grab,mod}.rs
    wm_client/{focus_query,mod}.rs
    compositor_client/{deliver,mod}.rs
    mod.rs
  state/{global,grabs,subscriptions,mod}.rs
  setup/{discover,run,mod}.rs
  server/parse_req.rs server/respond.rs
  server/runner.rs server/mod.rs
  server/handlers/{health,grab_request,
                   grab_release,subscribe,mod}.rs
  main.rs
```

Pinned to one CPU. SPSC ring per driver source; deterministic priority order at drain time.

Acceptance:
- Builds clean.
- Manifest signed.
- PS/2 keypress arrives at the focused app within 1 ms (measured via timestamp pair in the audit log).

### B5. capsule_wm

Window table + focus + z-order + lifecycle.

Layout:
```
src/
  protocol/...
  window/
    table/{insert,remove,lookup,mod}.rs       -- (owner_pid, window_id) keyed
    state/{geom,title,kind,visibility,mod}.rs
    lifecycle/{open,close,minimize,
               maximize,restore,mod}.rs
    kind/{normal,dialog,tooltip,popup,mod}.rs
    mod.rs
  focus/
    model/{stack,grab,mod}.rs
    hit_test/{point_in_window,
              topmost_at,mod}.rs
    keyboard_grab/{request,release,mod}.rs
    mod.rs
  z_order/
    stack/{raise,lower,topmost,mod}.rs
    mod.rs
  geometry/
    rect/{intersect,union,mod}.rs
    constrain/{display_bounds,
               min_max_size,mod}.rs
    snap/{edges,half,quarter,mod}.rs
    mod.rs
  compositor_client/{wire,header,seq,
                     scene_submit,focus_set,
                     mod}.rs
  state/{global,subscriptions,mod}.rs
  setup/{discover,run,mod}.rs
  server/parse_req.rs server/respond.rs
  server/runner.rs server/mod.rs
  server/handlers/{health,window_open,
                   window_close,window_move,
                   window_resize,window_focus,
                   window_raise,
                   lifecycle_subscribe,mod}.rs
  main.rs
```

Window IDs are `(owner_pid, local_id)`. WM does NOT own the surface; the app owns it and shares to the compositor through the surface registry. WM only carries window state (geometry, focus, z, lifecycle).

Acceptance:
- Builds clean.
- Manifest signed.
- A programmatic test capsule opens a window, receives focus, gets a routed keypress, closes; the audit log captures the full chain.

### B6. capsule_driver_intel_gfx (first slice)

After virtio_gpu is shipping and the compositor + wm + input loop is stable on the QEMU lane, start the hardware GPU driver. First slice covers display engine only: mode set, scanout, cursor plane. 2D blit and 3D arrive later.

Same broker grant set as virtio_gpu. Registers `gfx.primary` (same name; the scheduler picks whichever driver claimed the device first; on QEMU virtio_gpu wins, on Intel hardware intel_gfx wins).

Same layout shape as virtio_gpu, swap `device/mmio/` to Intel's register file (DISPLAY_BASE, PLANE_*, PIPE_*, TRANSCODER_*).

Acceptance:
- Builds clean.
- Manifest signed.
- Boot on real Intel hardware (or QEMU with `-vga none -device intel-iommu` and the Intel display passthrough) brings up a real scanout.

## Multi-CPU concurrency model (binding for B3)

| Thread | CPU | Lock pattern |
|---|---|---|
| compositor scene worker | 0 | sequence lock over snapshot pointer |
| compositor render worker N | 1..N-1 | per-tile work-stealing queue |
| compositor present submit | 0 | reads scene snapshot under sequence lock |
| input_router | one fixed | SPSC ring per source |
| gfx driver MMIO writer | one fixed | single writer per device, no lock |

Compositor's scene worker is the only writer to the scene graph. Render workers and present submit are readers under a sequence lock. If a render worker observes a torn snapshot, it spins until the sequence is even again. This is the only correct pattern; do not introduce a global mutex on the hot path.

## Multi-arch rules (binding for B1)

The eight kernel syscalls go through `src/arch/Arch::*` for:
- per-display vsync timer (x86_64 APIC timer, aarch64 generic timer, riscv64 mtimecmp/sstc)
- IRQ ack on VBlank IRQ (x86_64 LAPIC EOI, aarch64 GICv3 EOIR1, riscv64 PLIC complete)
- DMA coherency barrier (x86_64 MFENCE, aarch64 DSB SY, riscv64 fence)
- user mmap flags (target-arch matrix already in `src/arch/`)

The wire (SurfaceDescriptor, InputEvent) is byte-identical across arches. Little-endian everywhere. No arch-specific structs in the userland surface.

## Build evidence per capsule (same as Plan A)

1. `make -B nonos-mk-<slug>` builds with zero warnings, three triples.
2. `make nonos-mk-<slug>-sign` produces cert + manifest.
3. Row in `docs/production-roadmap/capsule_integration_matrix.md`.
4. README contract section.
5. New gate in `nonos-ci/run-static-checks.sh`.
6. `init/entry.rs` cfg-gated spawn call ordered before Rusty's capsules.
7. QEMU serial trace.

## Order of attack

1. B1 kernel syscalls + surface registry. Until these land, nothing else compiles.
2. B2 virtio_gpu. Compositor needs it to claim a real scanout.
3. B3 compositor. Heaviest piece.
4. B4 input_router. Can start in parallel with B3 once protocol surface is frozen.
5. B5 wm. Depends on compositor + input_router being callable.
6. B6 intel_gfx first slice. After everything else is stable on QEMU.

## Don't do

- Don't expand the kernel surface beyond the eight syscalls. If you find yourself wanting a ninth, write the spec, get Rusty's sign-off, then add it.
- Don't put compositor scene logic in the kernel.
- Don't share a mutable structure across CPUs without an atomic-snapshot pattern.
- Don't add `#[allow(dead_code)]` or `#[allow(unused)]`. Fix by narrowing or completing the code path.
- Don't ship a docs/ file with the same content as a README. Capsule contract goes in the capsule's README.

## What is hard about this track

The four real risks, in order:

1. **Sequence-locked scene snapshot under multi-CPU readers.** Get the snapshot reader-writer pattern wrong and rendered frames tear or the compositor deadlocks. Mitigation: write the sequence lock first, test it under fuzzing against a stub scene worker before any rendering exists.
2. **Surface registry refcount race across capsules.** A shares to B, A exits, B holds; if the kernel registry refcount is wrong the buffer leaks or freed-while-used. Mitigation: refcount lives only in the kernel registry, accessed only through atomic CAS; share/release is a single kernel call, no userland CAS.
3. **Vsync source timing accuracy.** On QEMU the timer drifts. On real hardware VBlank latency varies. Compositor frame pacer must handle missed deadlines without falling further behind. Mitigation: deadline catchup mode in the pacer (skip a frame if behind by more than one vblank period).
4. **GPU command submission correctness.** virtio_gpu fences must be honored or transfer_to_host races set_scanout and the display shows a half-blit. Mitigation: every submission carries a fence id; flush waits on the fence before the next submission.

If any of these four go wrong it shows up as visible tearing, freezes, or memory corruption. Test each in isolation before integrating.
