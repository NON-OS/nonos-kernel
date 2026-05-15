# capsule_about

## Role

`capsule_about` is a userland app capsule that owns the About window loop and
routes frame work to toolkit over IPC.

```text
about endpoint (4710)
	|
	v
capsule_about -- mk_ipc_call --> toolkit endpoint (4610)
	|
	`-- mk_yield bounded loop
```

## Microkernel contract

The capsule uses the following Mk syscall contract:

- `MkIpcRecv` for app endpoint receive loop.
- `MkIpcCall` for toolkit UI frame routing.
- `MkYield` for non-busy loop progression.
- `MkDebug` for app migration markers.
- `MkExit` for deterministic parked-exit path.

## Interface contract

App-owned constants:

- `APP_ABOUT_ENDPOINT = 4710`
- `TOOLKIT_ENDPOINT = 4610`
- `APP_OP_UI_FRAME = 1`

Behavior:

- Emits `app ui owner` and `toolkit ui route` markers.
- Receives on `APP_ABOUT_ENDPOINT`.
- Routes UI frame work through `mk_ipc_call(TOOLKIT_ENDPOINT, ...)`.

## Authority

`CAPSULE_REQUIRED_CAPS` status: parked-mask status at app skeleton parity.
No MMIO/IRQ/DMA/PIO/admin/network authority is requested by this capsule.

## Privacy and persistence

- No persistent storage.
- No cross-session identity cache.
- No direct framebuffer mapping.

## Runtime lifecycle

- Start: emit ownership marker and send toolkit UI frame op.
- Run: bounded receive/yield loop on app endpoint.
- Exit: on parked `ENOTSUP`, emit marker and call `MkExit`.

## Failure model

- Negative receive return values yield and retry.
- `ENOTSUP` transitions to deterministic exit.
- No panic-based control path is required for steady-state operation.

## Current implemented surface

- App endpoint loop (`mk_ipc_recv`).
- Toolkit routing (`mk_ipc_call` with `APP_OP_UI_FRAME`).
- Marker emission (`app ui owner`, `toolkit ui route`, `ipc parked`).

## Wire format

- Toolkit request payload: one byte op (`APP_OP_UI_FRAME`).
- Toolkit response buffer: fixed 16-byte scratch reply.
- App receive buffer: fixed 256-byte bounded message buffer.

## State ownership

`capsule_about` owns only transient loop-local buffers and marker emission. No
kernel-global or cross-capsule mutable state is owned.

## Operating rules

- Never access framebuffer or display MMIO directly.
- Route UI operations only through toolkit IPC.
- Keep loop bounded via receive/yield pattern.

## Release target

Build-only app-wave target with signed capsule artifacts and static-gate
compliance.

## Release evidence

- `cargo +nightly check --manifest-path userland/capsule_about/Cargo.toml --target userland/x86_64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec`
- `cargo +nightly check --manifest-path userland/capsule_about/Cargo.toml --target userland/aarch64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec`
- `cargo +nightly check --manifest-path userland/capsule_about/Cargo.toml --target userland/riscv64-nonos-user.json -Z build-std=core,alloc -Z json-target-spec`
- `make nonos-mk-about`
- `make nonos-mk-about-sign`

## Release checklist

- `APP_OP_UI_FRAME` defined in app runtime.
- `mk_ipc_recv(APP_ABOUT_ENDPOINT, ...)` present.
- `mk_ipc_call(TOOLKIT_ENDPOINT, ...)` present.
- Marker strings required by migration checks are present.

## Explicit non-goals today

- No direct graphics device ownership.
- No desktop policy ownership.
- No persisted configuration database.

## Verification

- `nonos-ci/run-static-checks.sh`
