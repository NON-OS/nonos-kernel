# Capsule integration matrix

Truth-state of every userland crate against the kernel. The
matrix is the contract used by the static gates: a Make target
without an entry here, or an entry that overstates integration
state, fails CI.

State labels

- `library` — not a capsule; consumed by other crates only
- `build-only` — compiles cleanly but is not embedded or spawned
- `embedded` — kernel image carries the binary via `include_bytes!`
- `spawned` — an `init/entry.rs` path spawns the capsule at boot
- `client` — a kernel-side module sends/receives the IPC envelope
- `smoke` — a profile + harness drives the capsule end-to-end

Promotion rule: a row may only claim a state when every label to
its left is also true (e.g. `smoke` requires `client + spawned +
embedded + build-only`).

## Active surfaces

| # | Capsule / crate | Binary target | Make target | Userland endpoint | Kernel feature | Kernel embed module | Kernel spawn path | Kernel client | Boot/runtime smoke | State | Warnings | Blocker | Next required slice |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `userland/libc` | rlib | `nonos-mk-libc` | n/a | n/a | n/a | n/a | n/a | n/a | library | 0 | none | none — consumed by every capsule |
| 2 | `userland/marketplace_abi` | rlib | `nonos-mk-marketplace-abi` | n/a | n/a | n/a | n/a | n/a | n/a | library | 0 | none | none — consumed by `capsule_market` and the host CLI |
| 3 | `userland/capsule_proof_io` | `proof_io` | `nonos-mk-proof-io` | (boot proof writer) | `nonos-capsule-proof-io` | `src/userspace/init/proof_io_*` | `src/userspace/init/entry.rs` | n/a (it speaks back over the proof channel) | included in every capsule profile | embedded + spawned | 0 | none | none — baseline |
| 4 | `userland/capsule_ramfs` | `ramfs` | `nonos-mk-ramfs` | `ramfs.ipc` | `nonos-capsule-ramfs` | `src/fs/ramfs_capsule/` | `src/userspace/init/entry.rs` (under feature) | `src/fs/ramfs_capsule/client/` | `microkernel-ramfs-smoketest` profile + `nonos-mk-ramfs-test` | smoke | 0 | none | runtime-proof on hardware |
| 5 | `userland/capsule_keyring` | `keyring` | `nonos-mk-keyring` | `keyring.ipc` | `nonos-capsule-keyring` | `src/security/keyring_capsule/` | `src/userspace/init/entry.rs` (under feature) | `src/security/keyring_capsule/client/` | `microkernel-keyring-smoketest` profile + `nonos-mk-keyring-test` | smoke | 0 | none | runtime-proof on hardware |
| 6 | `userland/capsule_entropy` | `entropy` | `nonos-mk-entropy` | `entropy.ipc` | `nonos-capsule-entropy` | `src/security/entropy_capsule/` | `src/userspace/init/entry.rs` (under feature) | `src/security/entropy_capsule/client/` | `microkernel-entropy-smoketest` profile + `nonos-mk-entropy-test` | smoke | 0 | none | reseed runtime-proof |
| 7 | `userland/capsule_crypto` | `crypto` | `nonos-mk-crypto` | `crypto.ipc` | `nonos-capsule-crypto` | `src/security/crypto_capsule/` | `src/userspace/init/entry.rs` (under feature) | `src/security/crypto_capsule/client/` | `microkernel-crypto-hash-smoketest` + `nonos-mk-crypto-hash-test` | smoke | warns on the in-flight Ed25519-verify branch (separate slice) | none for the hash surface; sign/verify needs its own slice | finish in-flight Ed25519 verify slice |
| 8 | `userland/capsule_vfs` | `vfs` | `nonos-mk-vfs` | `vfs.ipc` | `nonos-capsule-vfs` | `src/fs/vfs_capsule/` | `src/userspace/init/entry.rs` (under feature) | `src/fs/vfs_capsule/client/` | `microkernel-vfs-smoketest` + `nonos-mk-vfs-test` | smoke | 0 | none | runtime-proof on hardware, persistence backing |
| 9 | `userland/capsule_driver_virtio_rng` | `driver_virtio_rng` | `nonos-mk-virtio-rng` | `driver.virtio_rng` | `nonos-capsule-driver-virtio-rng` | `src/hardware/virtio_rng_capsule/` | `src/userspace/init/entry.rs` (under feature) | `src/hardware/virtio_rng_capsule/client/` | `microkernel-driver-virtio-rng-smoketest` + `nonos-mk-driver-virtio-rng-test` | smoke | 0 | none — QEMU runtime-proof outstanding | run smoke on a real virtio-rng device |
| 10 | `userland/capsule_driver_virtio_blk` | `driver_virtio_blk` | `nonos-mk-virtio-blk` | `driver.virtio_blk0` | none yet | none yet | none yet | none yet | none yet | build-only | 0 | kernel embed/spawn/client + boot smoke not written | task #52 — `src/hardware/virtio_blk_capsule/` mirror of `virtio_rng_capsule` |
| 11 | `userland/capsule_market` | `market` | `nonos-mk-market` (+ `nonos-mk-market-dev`) | `market.index` | none yet | none yet | none yet | none yet | none yet | build-only | 0 | kernel embed/spawn + thin IPC client + boot smoke not written | task #48 / #49 — kernel feature `nonos-capsule-market`, embed + spawn + client (healthcheck / load_index / list_apps / get_app / get_release / install_ready) + boot smoke driving `signed empty index`, `signed preview index`, `mutated body`, `serial rollback`, `untrusted operator` |
| 12 | `tools/marketplace-index` | host bin | `nonos-mk-marketplace-index-tool` | n/a (host CLI) | n/a | n/a | n/a | n/a | `tools/ci/marketplace_index_smoke.sh` + `cargo test --test wire_layout` | host tool | 0 | none | none — operator workflow lives in `docs/architecture/capsule_marketplace.md` |

## Parked surfaces

| # | Capsule / crate | State | Reason |
|---|---|---|---|
| W | `userland/capsule_wallpaper` | parked | feature `nonos-capsule-wallpaper` exists but the capsule is not on any active baseline; will return after the framebuffer broker primitive lands (driver task #4 / `MkFramebufferMap`) |

## Promotion checklist

For a row to advance from `build-only` to `embedded`:
- a `nonos-capsule-<name>` feature in the kernel `Cargo.toml`
- an `embed.rs` (or equivalent) under the kernel module that
  `include_bytes!`s the userland binary
- a `cargo build` of `microkernel-<name>` profile that is green

For `embedded` → `spawned`:
- a `spawn_<name>_capsule` function on the kernel side
- a cfg-guarded call in `src/userspace/init/entry.rs`
- the static-gate test that the call is feature-gated

For `spawned` → `client`:
- `src/<area>/<name>_capsule/client/` with the IPC transport and
  one helper per supported op
- the kernel-side error mapper for the capsule's errno set

For `client` → `smoke`:
- a `microkernel-<name>-smoketest` profile that depends on the
  capsule embed + the proof_io capsule
- an `entry.rs` smoke arm that exercises the client surface and
  emits PASS/FAIL on serial
- a `nonos-mk-<name>-test` Make target driving the smoke

A row that overstates its state fails the matrix-coverage gate in
`tools/ci/run-static-checks.sh`.
