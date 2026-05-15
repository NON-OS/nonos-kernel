# capsule_wallpaper

## Role

`capsule_wallpaper` is a long-lived wallpaper service capsule. It receives IPC
requests for wallpaper updates, policy changes, and fades, then pushes updates
to compositor using a full-screen shared surface.

```text
desktop_shell policy hints
  |
  v
wallpaper capsule -- decode + state --> shared ARGB8888 surface
  |                                   |
  `------------ damage commit --------'
       |
       v
        compositor layer 0
```

## Microkernel contract

The capsule uses the following Mk syscalls:

- `MkIpcRecv` receives requests on `service:4408:wallpaper`.
- `MkIpcSend` replies on `reply:4409:endpoint.wallpaper.reply`.
- `MkIpcCall` sends compositor requests (`scene_submit`, `damage_commit`).
- `MkServiceLookup` resolves `desktop_shell` and `compositor` ports.
- `MkMmap`, `MkSurfaceRegister`, and `MkSurfaceShare` own the wallpaper
  surface lifecycle.
- `MkYield` drives non-busy event loop behavior.

The kernel does not own wallpaper policy or decode state.

## Interface contract

Ops:

- `HEALTHCHECK`
- `SET_WALLPAPER`
- `GET_WALLPAPER`
- `SET_POLICY`
- `FADE`

`SET_WALLPAPER` supports two request forms:

- 8-byte solid-color payload (`argb`, pad)
- decode payload (`kind`, `width`, `height`, `payload_len`, bytes) where
  `kind` = PNG/BMP/LZ4_RAW/JPEG and bytes are decoded through `nonos_toolkit`

## Authority

The manifest currently requests `CAPSULE_REQUIRED_CAPS = 0x1919`
(`CoreExec|IPC|Memory|Debug|GraphicsDisplayQuery|GraphicsSurfaceCreate`).
No MMIO/IRQ/DMA/PIO/filesystem/network/admin authority is requested.

## Runtime lifecycle

- Discovers `desktop_shell` and `compositor` services during setup.
- Allocates and registers one full-screen ARGB8888 surface.
- Shares the surface handle and submits it as the bottom compositor layer.
- Applies updates in place and sends compositor damage commits.
- Maintains current color, policy, and fade timeline in capsule state.

## Current implemented surface

- Full op dispatch for `HEALTHCHECK`, `SET_WALLPAPER`, `GET_WALLPAPER`,
  `SET_POLICY`, and `FADE`.
- Toolkit decode path for PNG/BMP/LZ4_RAW/JPEG inputs.
- Scene submit + damage commit compositor integration.
- Deterministic errno paths for malformed requests and unsupported state.

## Wire format

Request and response envelopes use fixed 20-byte headers with explicit payload
length. Payloads are little-endian:

- `SET_WALLPAPER`: either `argb:u32 pad:u32` or
  `kind:u32 width:u32 height:u32 payload_len:u32 payload_bytes`.
- `GET_WALLPAPER`: empty request, response includes active color and policy.
- `SET_POLICY`: policy enum payload.
- `FADE`: target color + duration payload.

## State ownership

The capsule owns current ARGB value, policy, fade timeline, decoded backing
surface, and compositor request sequencing. The kernel does not own any
wallpaper state.

## Operating rules

- Setup fails closed when required services are missing.
- Only bounded payload sizes are accepted.
- Surface writes stay inside the allocated ARGB backing buffer.
- Every visual state mutation emits compositor damage commit.

## Release target

Production wallpaper behavior requires deterministic op handling, stable bottom
layer scene ownership, fade/state consistency, and signed artifacts.

## Release evidence

- Triple-target compile checks on x86_64/aarch64/riscv64 user targets.
- `make nonos-mk-wallpaper` and `make nonos-mk-wallpaper-sign`.
- Static checks run with any unrelated blockers explicitly tracked in plan logs.

## Release checklist

- Healthcheck + all wallpaper ops are deterministic.
- Setup discovery and scene submit are verified.
- Fade transitions and damage commits are wired.
- Signed cert/manifest artifacts are present.

## Explicit non-goals today

No wallpaper file catalog, no persistent wallpaper database, no kernel-managed
pixel cache, and no window-manager policy ownership.

## Privacy and persistence

- No file-system persistence.
- No input capture.
- No window-policy ownership.
- Pixels exist only in mapped userland surface memory and compositor-visible
  surface handles.

## Failure model

- Invalid request envelopes return `E_INVAL`.
- Unknown opcodes return `E_BAD_OP`.
- Decode failures return `E_INVAL`.
- Setup fails closed if required services or surface allocation are unavailable.

## Verification

- Triple-target build check:
  `cargo +nightly check --manifest-path userland/capsule_wallpaper/Cargo.toml --target userland/{x86_64,aarch64,riscv64}-nonos-user.json -Z build-std=core,alloc -Z json-target-spec`
- Release build target: `make nonos-mk-wallpaper`
- Sign target: `make nonos-mk-wallpaper-sign`
- Static gate: `./nonos-ci/run-static-checks.sh`
