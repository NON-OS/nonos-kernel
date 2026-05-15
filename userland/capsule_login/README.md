# capsule_login

## Role

`capsule_login` is the pre-desktop authentication gate capsule. It validates
session start and end requests before userland shell flow continues.

## Microkernel contract

The capsule uses IPC and memory mechanisms only:

- `MkIpcRecv` receives requests on `service:4416:login`.
- `MkIpcSend` returns responses on `reply:4417:endpoint.login.reply`.
- `MkServiceLookup` discovers `keyring`, `desktop_shell`, and `compositor`.
- `MkIpcCall` delegates key validation and emits shell/compositor signals.

The kernel does not keep login session state. It routes IPC and enforces the
signed capsule manifest.

## Interface contract

Ops:

- `HEALTHCHECK`
- `START_SESSION`
- `END_SESSION`
- `GET_STATE`

## Authority

The manifest grants `IPC` and `Memory` through `CAPSULE_REQUIRED_CAPS = 0x18`.
No device, MMIO, IRQ, DMA, PIO, network, filesystem, admin, or debug authority
is requested.

## Runtime lifecycle

On boot the capsule discovers dependencies, starts locked, and serves IPC. A
successful `START_SESSION` unlocks runtime state for one owner pid and a single
key id. `END_SESSION` relocks state and clears ownership metadata.

## Current implemented surface

- Bounded, deterministic lock/session state machine.
- Keyring-backed unlock/lock calls via `OP_UNLOCK` and `OP_LOCK`.
- Desktop shell notify signal and compositor damage ping on transitions.
- Deterministic errors for malformed payloads, invalid ownership, and busy
  session transitions.

## Wire format

Request/response envelopes use fixed 20-byte headers and explicit payload
length. Payloads are little-endian:

- `START_SESSION`: `key_id:u32`
- `END_SESSION`: empty body
- `GET_STATE`: empty body, response body `state:u32 owner_pid:u32 session_serial:u32`

## State ownership

The capsule owns lock state, owner pid, key id, and session serial. The kernel
and peers do not mutate session state directly.

## Operating rules

- Only one active session exists at a time.
- `END_SESSION` requires caller pid ownership.
- Key validation is delegated to keyring; no credential bytes are stored in the
  capsule.
- Transition notifications are best-effort IPC calls bounded by reply status.

## Release target

A production-ready login capsule provides deterministic lock/unlock transitions,
keyring delegation, shell/compositor signaling on session changes, signed
artifacts, and CI/static-gate coverage.

## Release evidence

- Build checks on x86_64/aarch64/riscv64 user targets.
- `make nonos-mk-login` and `make nonos-mk-login-sign`.
- Static checks run with known unrelated blockers documented in the plan.

## Release checklist

- Session start/end/state operations are deterministic.
- Ownership guard on end-session is enforced.
- Keyring unlock/lock delegation path is exercised.
- Sign artifacts and matrix row are updated.

## Explicit non-goals today

No password UI rendering, multi-factor auth, persistent login storage, or
kernel-resident auth policy.
