# Capsule integration matrix

Truth-state of every userland crate against the kernel. The
matrix is the contract used by the static gates: a Make target
without an entry here, or an entry that overstates integration
state, fails CI.

State labels

- `library` — not a capsule; consumed by other crates only
- `source-only` — source directory exists but no buildable binary is wired
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
| 13 | `userland/capsule_driver_virtio_net` | `driver_virtio_net` | `nonos-mk-virtio-net` | `driver.virtio_net0` | `nonos-capsule-driver-virtio-net` | `src/hardware/virtio_net_capsule/` | `src/userspace/init/entry.rs` (under feature) | `src/hardware/virtio_net_capsule/client/` (healthcheck / link_status / mac_address / tx_packet / rx_packet) | `microkernel-driver-virtio-net-smoketest` profile + `nonos-mk-driver-virtio-net-test` (`tests/boot/virtio_net_round_trip.sh` attaches a `virtio-net-pci` device backed by `-netdev user`) | smoke | 0 | none — QEMU runtime-proof outstanding | run smoke on real hardware once a network broker primitive lands |
| 14 | `userland/capsule_wallpaper` | `wallpaper` | `nonos-mk-wallpaper` | n/a (one-shot) | `nonos-capsule-wallpaper` | `src/userspace/capsule_wallpaper/` | `src/userspace/init/entry.rs` (replaces proof_io launch under `nonos-wallpaper-smoketest`) | n/a — drives the kernel graphics syscall surface from CPL=3 directly (`display_dimensions` / `surface_create` / `surface_map` / `surface_present_full` / `surface_destroy`) | `microkernel-wallpaper-smoketest` profile + `nonos-mk-wallpaper-test` | smoke | 0 | only `display_dimensions` is wired; remaining graphics syscalls stay parked (`ENOTSUP`) | land RB2-RB3 real backend path, then run QEMU/hardware round-trip smoke |
| 15 | `userland/capsule_driver_ps2_input` | `driver_ps2_input` | `nonos-mk-ps2-input` | `driver.ps2_kbd0` | `nonos-capsule-driver-ps2-input` | `src/hardware/ps2_kbd_capsule/` | `src/userspace/init/entry.rs` (under feature) | `src/hardware/ps2_kbd_capsule/client/` | `microkernel-driver-ps2-input-smoketest` profile + `nonos-mk-driver-ps2-input-test` (`tests/boot/ps2_input_round_trip.sh` injects scancodes via QEMU monitor) | smoke | 0 | runtime smoke not yet executed end-to-end | run smoke under QEMU on Linux, then on real hardware |
| 16 | `userland/capsule_driver_xhci` | `driver_xhci` | `nonos-mk-xhci` | `driver.xhci0` | `nonos-capsule-driver-xhci` | `src/hardware/xhci_capsule/` | `src/userspace/init/entry.rs` (under feature) | `src/hardware/xhci_capsule/client/` (`healthcheck`, `controller_status`, `port_status`) | `microkernel-driver-xhci-smoketest` profile + `nonos-mk-driver-xhci-test` (`tests/boot/xhci_round_trip.sh` boots `-device qemu-xhci`); P0 controller bring-up only — no slot enable, no transfers, no enumeration | smoke | 0 | runtime smoke not yet executed; INTx-only because the broker has no MSI/MSI-X grant primitive yet | P1: slot enable / address device / EP0 / GetDescriptor. P4 broker work for MSI-X. |
| 17 | `userland/capsule_about` | n/a | none yet | n/a | none yet | none yet | none yet | none yet | none yet | source-only | 0 | directory exists but no buildable capsule target is wired | either remove stale directory or add crate + `nonos-mk-about` target |

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
