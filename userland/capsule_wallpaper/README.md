# capsule_wallpaper

## Role

`capsule_wallpaper` is a parked graphics smoketest capsule. It exists to prove
that a userland process can call the graphics syscall surface, create a
surface, map it, fill pixels, present, destroy the surface, and report PASS.

It is not a normal production service capsule today.

```text
wallpaper smoketest
    |
    | graphics Mk calls
    v
surface create -> map -> fill -> present -> destroy
    |
    `-- MkDebug PASS/FAIL markers
```

## Microkernel contract

The capsule calls the graphics surface API exposed through libc:

- display dimensions
- surface create
- surface map
- full-surface present
- surface destroy
- `MkDebug` for PASS/FAIL markers
- `MkExit` for completion status

`Capsule.parked` records that this is smoketest-only. It has no production
spawn path and no production manifest until graphics promotion is complete.

## Interface contract

| Call | Purpose |
|---|---|
| display dimensions | discover framebuffer dimensions |
| surface create/map/present/destroy | exercise the graphics surface lifecycle |
| `MkDebug` / `MkExit` | emit smoke markers and status |

## Authority

There is no production `CAPSULE_REQUIRED_CAPS` mask in this directory today
because the capsule is parked. A future production version must declare only
the graphics, IPC, and memory authority needed by the graphics contract.

## Privacy and persistence

The capsule writes a solid color into a transient mapped surface. It does not
read user files, inspect windows, persist pixels, capture input, or store
display state.

## Runtime lifecycle

The capsule runs only under the wallpaper smoke profile, creates one surface,
fills it, presents it, destroys it, emits PASS/FAIL markers, and exits.

## Failure model

Graphics `ENOTSUP` is treated as parked and exits cleanly. Any failed surface
operation emits a specific failure marker and exits non-zero.

## Current implemented surface

- Parked smoketest source exists.
- Exercises the graphics syscall surface when the wallpaper smoke profile is
  enabled.
- Emits PASS/FAIL markers over the debug channel.
- Exits after the smoke run.

## Wire format

There is no long-running IPC wire protocol. The visible artifacts are graphics
syscall return values and PASS/FAIL markers emitted through `MkDebug`.

## State ownership

The capsule owns one transient surface id and mapped surface pointer during the
smoke. The graphics backend owns framebuffer mapping. No wallpaper pixels are
persisted.

## Operating rules

- Treat `ENOTSUP` as parked graphics, not success of rendering.
- Destroy the surface on every mapped failure path.
- Do not add desktop policy to this smoke capsule.

## Release target

The finished wallpaper capsule, if retained, is a signed graphics smoke
artifact with an explicit manifest, feature-gated spawn, deterministic surface
lifecycle, and no desktop policy. If a real wallpaper service is needed, it
should be promoted as a separate UI capsule with storage and permissions
defined up front.

## Release evidence

Release evidence is the graphics smoke marker sequence, surface lifecycle
proof, and static proof that framebuffer mapping remains kernel-owned.

## Release checklist

- Surface create/map/present/destroy smoke passes.
- Failure markers identify the failed graphics step.
- Static gate confirms no direct framebuffer mapping in userland.
- Parked status is removed only with a real manifest and spawn contract.

## Explicit non-goals today

No compositor, window manager, image loader, theme engine, desktop shell,
input handling, persistent wallpaper storage, or production spawn path lives
here.

## Verification

- Build/smoke target: `nonos-mk-wallpaper-test` when the graphics smoke slice
  is active.
- Static gate: `bash nonos-ci/run-static-checks.sh`
- Promotion check: this capsule must stay marked parked until it has a real
  manifest, capability mask, and production spawn contract.
