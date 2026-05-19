# capsule_calculator

## Role

`capsule_calculator` is a real production application capsule built on
`nonos_app_skeleton`. It owns integer arithmetic with two decimal places of
scaling. The capsule keeps its own state, has no globals, and reads keyboard
input through the toolkit. The capsule routes UI rendering through the toolkit
IPC path rather than through any kernel UI code.

```text
calculator app
    |
    | UI frame request
    v
toolkit endpoint
    |
    `-- app event loop on app endpoint
```

## Microkernel contract

The capsule uses the basic Mk surface that every app skeleton uses:

- `MkIpcCall` sends a UI frame request to the toolkit endpoint.
- `MkIpcRecv` receives application messages on the app endpoint.
- `MkYield` backs off when no message is available.
- `MkDebug` emits ownership and proof markers.
- `MkExit` exits when the IPC surface is parked.

The active spawn path is the standard `nonos_app_skeleton::run` entry point.

## Interface contract

| Call | Purpose |
|---|---|
| `MkIpcCall` to toolkit | request a UI frame through userland toolkit policy |
| `MkIpcRecv` on app endpoint | receive app input messages |
| `MkYield`, `MkDebug`, `MkExit` | cooperative loop and proof markers |

The keyboard surface accepts digits 0 through 9, the operators plus, minus,
star, slash, equals, the decimal point, Enter, AC, and Esc.

## Authority

The capsule keeps the narrow capability set defined by the app skeleton. It
does not request graphics, network, filesystem, or device authority. It does
not request direct framebuffer access. All UI authority is delegated to the
toolkit through IPC.

## Privacy and persistence

The capsule keeps no profile, no settings, no files, no telemetry, and no
persistent UI state. The current value, the entered digits, and the pending
operator are local owned state and disappear with the process.

## Runtime lifecycle

The capsule emits ownership markers, enters the app skeleton run loop, and
processes input events through `MkIpcRecv` until the IPC surface is parked. On
clean shutdown the runtime state is gone with the process. On error the
capsule emits a marker and exits.

## Failure model

Toolkit failure is observable through proof markers and never grants the
capsule a fallback framebuffer path. Invalid input is handled by the calculator
state machine and never escalates to a kernel call.

## Current implemented surface

- Source for the calculator state machine, button layout, key map, theme,
  formatter, and event loop.
- Integer math with two decimal places of scaling.
- Keyboard surface for digits, operators, AC, Esc, and Enter.
- Runs above `nonos_app_skeleton` with toolkit-only UI.

## Wire format

Input messages arrive on the app endpoint as toolkit input events. UI requests
go out on the toolkit endpoint. The exact payload layout is owned by the
toolkit and the app skeleton library.

## State ownership

The capsule owns the calculator state machine. The toolkit owns rendering. The
compositor owns scene and focus. The kernel owns none of the calculator state.

## Operating rules

- Route UI through toolkit IPC only.
- Do not request direct framebuffer authority.
- Keep all app state volatile.
- Do not introduce kernel UI exports for this app.

## Release target

The release version is a signed application capsule with `Capsule.mk`, signed
manifest, feature gated spawn, toolkit only UI rendering, no direct framebuffer
authority, and smoke proof that calculator policy stays out of the kernel.

## Release checklist

- `Capsule.mk` and signed manifest exist.
- Toolkit IPC smoke passes.
- Feature gated spawn is present.
- Static gate confirms no kernel app UI exports.

## Explicit non-goals today

No production manifest, signed spawn path, persistent settings, network
access, filesystem access, graphics driver access, or direct framebuffer
authority belongs in this directory.

## Verification

- Build: `cargo build --manifest-path userland/capsule_calculator/Cargo.toml`
- Static gate: `bash nonos-ci/run-static-checks.sh`
- Promotion check: add `Capsule.mk`, manifest signing, feature gated spawn,
  and smoke proof before claiming production app status.
