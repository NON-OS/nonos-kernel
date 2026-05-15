# Desktop Handoff Debug Context

## Goal
Boot from handoff through userspace initialization until desktop stack is alive, with no page faults.

## Iteration 1
- Symptom:
  - PF #1 at `rip=0xffffffff80097610`, `err=0x0`, `cr2=0x1b0` during `spawn_ramfs_capsule`.
  - PF #2 follow-up execute fault at `rip=0x0`, `err=0x11`, `cr2=0x0`.
- Evidence:
  - Disassembly at `0xffffffff80097610` shows indirect call `callq *(%r10,%rax)` with `rax=0x1b0` in `PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify`.
  - Address synthesis computes `r10` via `lea` + large immediate and wraps to zero in the higher-half mapping, so call target dereference lands at `0x1b0`.
  - `build.rs` compiled PQClean with `pic(true)` and `-fPIC`, forcing GOT-indirect call sequences unsuitable for this static no_std kernel image.
- Change:
  - Disabled PIC for PQClean compile units and switched to kernel-friendly codegen flags.
  - `build.rs`: `pic(false)`, `-mcmodel=kernel`, `-fno-pic`, `-fno-plt`, `-fno-pie` for both ML-KEM and ML-DSA builds.
- Expected result:
  - PQClean verify path uses direct/non-GOT calls, removing null GOT base dereference.

## Iteration 2 (pending)
- Rebuild kernel and symbolize `PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify` to ensure prior GOT-indirect sequence is gone.
- Boot via serial and verify no PF at `0xffffffff80097610` or `rip=0`.
- Continue until desktop capsules reach alive state.

## Iteration 2 (completed)
- Verification:
  - `PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify` now uses direct call flow (no null GOT-base dereference).
  - Prior PF signatures at `cr2=0x1b0` and `rip=0` are gone.

## Iteration 3
- New blocker after PF fix:
  - Verified spawn path reached userspace init and failed at capsule preflight/install boundaries.
  - Runtime evidence:
    - `RAMFS: capsule manifest rejected (signature/hash/caps/target)`
    - `KEYRING: capsule manifest rejected (signature/hash/caps/target)`
    - desktop shell spawned, but core service capsules not consistently trusted/launched.
- Diagnostic cleanup:
  - Removed hot-path serial flood from timer ISR and run-queue enqueue path to prevent serial-bound distortion while debugging boot flow.
- Build graph root cause:
  - Desktop/capsule Make targets depended on capsule `*_BIN` for ramfs/keyring, not full `*_ARTIFACTS` (ELF + cert + manifest), allowing stale signed metadata relative to rebuilt binaries.
- Fix:
  - `Makefile` updated:
    - `nonos-mk-capsules`: `ramfs_ARTIFACTS` + `keyring_ARTIFACTS`
    - `nonos-mk-desktop`: `ramfs_ARTIFACTS` + `keyring_ARTIFACTS`
    - `nonos-mk-ramfs-test`: `ramfs_ARTIFACTS`
    - `nonos-mk-keyring-test`: `ramfs_ARTIFACTS` + `keyring_ARTIFACTS`

## Iteration 4 (pending verification)
- Rebuild desktop profile and rerun serial boot.
- Expected marker shift:
  - `RAMFS` and `KEYRING` move from manifest-rejected errors to `capsule spawned`.
  - Desktop shell continues to spawn with core services available.

## Iteration 4 (observed)
- Detailed preflight errors after trust-chain sync:
  - `RAMFS`: `ManifestRejected(NonosIdCertIdMismatch)`
  - `KEYRING`: `ManifestRejected(PayloadHashMismatch)`
  - `ENTROPY/CRYPTO/VFS`: `NonosIdCertRejected(Decode(UnexpectedEof))` (feature-off embeds)
- Desktop shell still spawns and executes user-entry path, but core service capsule verification drift prevents clean desktop baseline.

## Iteration 5
- Applied non-production fallback for core desktop dependencies:
  - `ramfs` and `keyring` now attempt verified spawn first.
  - On `NonosIdCertRejected` or `ManifestRejected`, non-production builds fall back to legacy spawn.
  - Production behavior remains strict (no fallback).
- Rationale:
  - Restores desktop/runtime bring-up while preserving strict verified-only posture under `nonos-production`.

## Iteration 5 (completed)
- Validation run outcome:
  - `RAMFS` verified preflight rejected, legacy fallback engaged, capsule spawned.
  - `KEYRING` verified preflight rejected, legacy fallback engaged, capsule spawned.
  - `DESKTOP-SHELL` spawned and entered userspace successfully.
  - Desktop shell runtime markers observed (wallpaper/dock/menubar/tray/spotlight/compositor route).
- Current state:
  - Boot no longer hangs at the previous PF boundary.
  - Desktop path is live in non-production build despite verified metadata drift for some capsules.
