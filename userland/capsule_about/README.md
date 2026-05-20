# capsule_about

## Role

`capsule_about` is an application UI capsule skeleton. It proves that ordinary
application UI policy belongs in userland and routes through the toolkit IPC
path rather than through kernel UI code.

```text
about app
    |
    | UI frame request
    v
toolkit endpoint 4610
    |
    `-- app event loop on endpoint 4710
```

## Microkernel contract

The capsule uses the basic Mk IPC surface:

- `MkIpcCall` sends a UI-frame request to the toolkit endpoint.
- `MkIpcRecv` receives application messages on endpoint `4710`.
- `MkYield` backs off when no message is available.
- `MkDebug` emits proof markers.
- `MkExit` exits when the IPC surface is parked.

This directory currently has no `Capsule.mk`, so it is not a verified
production spawn target yet.

## Interface contract

| Call | Purpose |
|---|---|
| `MkIpcCall` to toolkit | request a UI frame through userland toolkit policy |
| `MkIpcRecv` on endpoint 4710 | receive app messages |
| `MkYield`, `MkDebug`, `MkExit` | cooperative loop and proof markers |

## Authority

There is no production `CAPSULE_REQUIRED_CAPS` mask in this directory today.
A promoted version should require only IPC and memory, plus whatever explicit
toolkit/app capability the manifest model assigns.

## Privacy and persistence

The capsule keeps no user profile, settings, files, telemetry, or persistent
UI state. Runtime messages are transient and disappear with the process.

## Runtime lifecycle

The capsule emits ownership markers, sends one toolkit request, then enters a
receive/yield loop until the IPC surface is parked or the app is replaced by a
promoted manifest-backed version.

## Failure model

Toolkit failure is observable through the proof markers and does not grant
fallback framebuffer access. `ENOTSUP` exits cleanly because this is still an
app-UI ownership proof.

## Current implemented surface

- Source exists for the app UI ownership proof.
- Calls the toolkit endpoint instead of kernel UI paths.
- Runs a small receive loop on the app endpoint.
- Exits cleanly when the IPC surface is parked.

## Wire format

The current app proof sends a one-byte UI-frame request to the toolkit endpoint
and receives app messages on endpoint `4710`. A promoted app protocol must
version its message format before release.

## State ownership

The capsule owns only its app-local message loop state. The toolkit owns UI
rendering. The compositor owns scene and focus policy. The kernel owns none of
the app UI state.

## Operating rules

- Route UI through toolkit IPC only.
- Do not request direct framebuffer authority.
- Keep app state volatile until a storage contract exists.
- Do not add kernel UI exports for this app.

## Release target

The finished about capsule is a signed application capsule with `Capsule.mk`,
manifest, feature-gated spawn, toolkit-only UI rendering, no direct framebuffer
authority, and smoke proof that app UI policy stays outside the kernel.

## Release evidence

Release evidence is a signed manifest, feature-gated spawn, toolkit IPC smoke,
and static proof that app UI policy does not appear in kernel exports.

## Release checklist

- `Capsule.mk` and signed manifest exist.
- Toolkit IPC smoke passes.
- Feature-gated spawn is present.
- Static gate confirms no kernel app-UI exports.

## Explicit non-goals today

No production manifest, signed spawn path, persistent settings, network
access, filesystem access, graphics driver access, or direct framebuffer
authority lives here.

## Verification

- Build: `cargo build --manifest-path userland/capsule_about/Cargo.toml`
- Static gate: `bash nonos-ci/run-static-checks.sh`
- Promotion check: add `Capsule.mk`, manifest signing, feature-gated spawn,
  and smoke proof before claiming production app status.
