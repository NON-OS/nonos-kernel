# capsule_proof_io

## Role

`capsule_proof_io` is the boot proof capsule. It gives the kernel a small,
signed userland process that can prove capsule spawn, CPL3 execution, and the
debug/proof channel without depending on storage, graphics, networking, or
drivers.

```text
kernel init
    |
    | verified spawn
    v
proof_io -- MkDebug --> serial proof stream
    |
    `-- MkExit
```

## Microkernel contract

The capsule uses the minimal Mk surface:

- `MkDebug` writes proof markers to the trusted boot/debug stream.
- `MkExit` terminates the process with an explicit status.
- The service endpoint is `service:4500:proof_io` for the manifest contract,
  but the current boot proof is one-shot and does not run a long IPC server.

The kernel owns verification, address-space creation, scheduling, and teardown.
The capsule proves that those mechanisms work from userland.

## Interface contract

| Call | Purpose |
|---|---|
| `MkDebug` | emit deterministic boot proof markers |
| `MkExit` | report proof result to the runtime |

## Authority

The manifest grants `IPC` and `Memory` (`CAPSULE_REQUIRED_CAPS = 0x18`). It has
no driver, MMIO, IRQ, DMA, PIO, filesystem, network, graphics, admin, or debug
policy authority beyond `MkDebug` proof output.

## Privacy and persistence

The capsule emits fixed proof markers only. It does not inspect user data,
persist state, read devices, or hold secrets. Its process state disappears at
exit.

## Runtime lifecycle

The capsule is spawned by the boot profile, writes fixed markers, and exits. It
does not remain resident, register a long-running service, or depend on other
capsules.

## Failure model

Any unexpected syscall failure is observable as a missing marker or non-zero
exit path in the boot proof. There is no recovery loop because the capsule is a
one-shot evidence artifact.

## Current implemented surface

- Included in capsule profiles as the baseline spawn proof.
- Executes in userland and emits deterministic proof markers.
- Exits explicitly after proof completion.
- Keeps the boot proof independent of larger subsystems.

## Wire format

There is no long-lived service protocol. The observable wire artifact is the
debug stream marker sequence emitted through `MkDebug`, followed by the process
exit status from `MkExit`.

## State ownership

The capsule owns only its stack/register state while running. It owns no
persistent store, no IPC server state, and no device state.

## Operating rules

- Keep marker text deterministic.
- Keep dependencies minimal enough to run before other services are trusted.
- Do not add driver, filesystem, network, or graphics dependencies.

## Release target

The finished proof capsule stays intentionally small: signed manifest, verified
spawn, deterministic userland marker emission, explicit exit status, and no
dependencies on storage, networking, graphics, or drivers. Its job is to make
the boot path auditable, not to become a diagnostics subsystem.

## Release evidence

Release evidence is the serial/debug marker sequence plus explicit exit status
under the capsule profile that includes `proof_io`.

## Release checklist

- Verified spawn from kernel init profile.
- Expected marker sequence appears on serial/debug output.
- Exit status is deterministic.
- Static gate confirms no Linux-shaped write syscall use.

## Explicit non-goals today

No service protocol, no storage, no graphics, no network, no driver authority,
and no general diagnostics console live here.

## Verification

- Build: `make -B nonos-mk-proof-io`
- Static gate: `bash nonos-ci/run-static-checks.sh`
- Runtime proof: every capsule profile that includes `proof_io` should show
  the expected proof markers on the serial/debug stream.
