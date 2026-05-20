# Boot-handoff Trust Ceremony — Iteration Context Log

**Plan:** `docs/superpowers/plans/2026-05-20-boot-handoff-trust-ceremony.md`
**Branch:** feature/bootloader-hardening
**Merge commit:** 72265e14d (parents 919127580 ours + 7d20c23d5 theirs)
**Started:** 2026-05-20

## Capsule set under ceremony (34 — from nonos-sign/tests/artifacts.rs)

| Slug (make)        | Prefix (key files)       | Boot-log name         |
|--------------------|--------------------------|-----------------------|
| proof-io           | proof_io                 | proof_io              |
| ramfs              | ramfs                    | RAMFS                 |
| keyring            | keyring                  | KEYRING               |
| entropy            | entropy                  | ENTROPY               |
| crypto             | crypto                   | CRYPTO                |
| vfs                | vfs                      | VFS                   |
| market             | market                   | MARKET                |
| driver-virtio-rng  | driver_virtio_rng        | DRIVER-VIRTIO-RNG     |
| driver-virtio-gpu  | driver_virtio_gpu        | DRIVER-VIRTIO-GPU     |
| driver-ps2-input   | driver_ps2_input         | DRIVER-PS2-INPUT      |
| driver-virtio-blk  | driver_virtio_blk        | DRIVER-VIRTIO-BLK     |
| driver-virtio-net  | driver_virtio_net        | DRIVER-VIRTIO-NET     |
| driver-xhci        | driver_xhci              | DRIVER-XHCI           |
| driver-e1000       | driver_e1000             | DRIVER-E1000          |
| net-l2             | net_l2                   | NET-L2                |
| net-ip             | net_ip                   | NET-IP                |
| net-udp            | net_udp                  | NET-UDP               |
| net-dhcp           | net_dhcp                 | NET-DHCP              |
| input-router       | input_router             | INPUT-ROUTER          |
| compositor         | compositor               | COMPOSITOR            |
| wm                 | wm                       | WM                    |
| desktop-shell      | desktop_shell            | DESKTOP-SHELL         |
| image-codec        | image_codec              | IMAGE-CODEC           |
| clipboard          | clipboard                | CLIPBOARD             |
| login              | login                    | LOGIN                 |
| wallpaper          | wallpaper                | WALLPAPER             |
| toolkit            | toolkit                  | TOOLKIT               |
| about              | about                    | APP-ABOUT             |
| calculator         | calculator               | APP-CALCULATOR        |
| terminal           | terminal                 | APP-TERMINAL          |
| file-manager       | file_manager             | APP-FILE-MANAGER      |
| text-editor        | text_editor              | APP-TEXT-EDITOR       |
| settings           | settings                 | APP-SETTINGS          |
| process-manager    | process_manager          | APP-PROCESS-MANAGER   |

## Boot iterations

(populated by Task 10 onward — one section per boot attempt)

## Tasks 1-7: Ceremony complete — 2026-05-20T16:21Z

- Wiped 282 stale artifacts (44 certs + 44 manifests + 1 policy + 98 pubs + 70 seeds + 25 keys/pubs).
- Generated TA pair (Ed25519 + ML-DSA-65).
- Generated 34 publisher pairs (68 seeds + 68 pubs).
- Built all 34 capsule ELFs in 78s, 0 failures.
- Sealed new policy (sha256 5fcaed0313565942eeeef366c2179aa57abd71acd5e44ab13aafc154300d48f0).
- Signed 34 certs + 34 manifests in 13s, 0 failures.
- `cargo test --release --test artifacts`: `on_disk_artifacts_verify_against_baked_policy ... ok`.

Chain is now locally self-consistent.

## Boots 1-4: trust-layer works, but kernel verifier has runtime non-determinism

Confirmed via 4 boot iterations:
- **Boot 1** (after Tasks 1-9): 25/31 spawn, 6 reject. RAMFS, CRYPTO, DRIVER-PS2-INPUT, COMPOSITOR, APP-ABOUT, APP-CALCULATOR rejected.
- **Boot 2** (after `cargo clean -p nonos_kernel` + rebuild + ESP): 23/31 spawn, 8 reject. RAMFS, KEYRING, ENTROPY, CRYPTO, DRIVER-VIRTIO-RNG, COMPOSITOR, TOOLKIT, APP-TEXT-EDITOR rejected.
- **Boot 3** (after `rm -rf target/x86_64-nonos` + full Phase B/C/D rebuild): 18/31 spawn, 13 reject. Including DESKTOP-SHELL, LOGIN, WALLPAPER, VFS, NET-L2/IP/UDP, ENTROPY, DRIVER-XHCI, APP-TERMINAL, APP-FILE-MANAGER.
- **Boot 4** (SAME kernel as Boot 3, no rebuild): 22/31 spawn, 9 reject. Including DRIVER-VIRTIO-BLK/NET, DRIVER-PS2-INPUT, NET-DHCP, CLIPBOARD, LOGIN, APP-PROCESS-MANAGER.

**Runtime non-determinism confirmed.** Boot 3 vs Boot 4 used the byte-identical `kernel_attested.bin` (sha256 e7c64b38…) yet rejected completely different sets of capsules. Common to all 4 boots: RAMFS + CRYPTO. Otherwise the set varies.

### Forensics that rule out the obvious

- On-disk chain is mathematically consistent (artifacts test `on_disk_artifacts_verify_against_baked_policy` passes — `cargo test --release --test artifacts`).
- Kernel binary embeds the on-disk ELF byte-for-byte (verified via python find/sha256 of embedded entropy ELF — sha256 matches on-disk exactly).
- Kernel binary embeds the on-disk cert + manifest byte-for-byte at exactly ONE location per capsule.
- Both signer (`nonos-sign`) and kernel use **blake3 1.8.5** (same Cargo.lock pinning).
- Manifest decoder reads `payload_hash` field correctly (validated against hex dump: blake3(elf) = `db87299c…` matches manifest bytes at offset 0x56).
- 0 TA failures across all 4 boots — Layer 1 (trust-anchor) is bulletproof.

### What this rules out

- ❌ Bad trust-anchor seed/pub pairing (Boots 1-4 have zero TA failures).
- ❌ Stale cert/manifest cache from before the ceremony (full nuke-and-rebuild done, kernel binary verified to embed current bytes).
- ❌ Wrong embed paths (each capsule's embed.rs points at the right file).
- ❌ Cargo incremental cache (boot 3 was a `rm -rf target/x86_64-nonos` fresh build, still failed).
- ❌ Build-order timing (boot 4 used boot 3's kernel verbatim, set changed anyway).
- ❌ ML-DSA randomized signatures causing manifest drift (would change all of cert+manifest at sign time, not at runtime).

### What this points at

The same kernel binary, the same embedded bytes, the same blake3 algorithm — but different verification outcomes per boot. **The bug is a kernel-side runtime issue.** Most likely culprits:

1. **Memory corruption** — embedded `&'static [u8]` slices are being clobbered between embed-time and verify-time. Each boot's corruption pattern is non-deterministic.
2. **Race condition in the spawn pipeline** — capsules are spawned concurrently and verifier shares mutable state without protection.
3. **ELF loader writing into the embedded ELF region** — relocations or section copies hitting the include_bytes! `.rodata` constants.
4. **A bug in the blake3 implementation** under no_std (kernel uses the `pure` feature) that produces wrong hashes under specific input alignment.

Per superpowers:systematic-debugging "3+ fixes failed" rule: stop attempting trust-ceremony fixes (already produced 4 different results); this is an **architectural bug** that needs targeted debugging on the verifier path itself. Trust ceremony is correct — the runtime is the broken layer.

## Recommended next steps (separate investigation)

1. Add `core::ptr::read_volatile`-based bytewise comparison + checksum logging in `src/security/capsule_manifest/verify/payload.rs` to print the actual computed hash vs expected hash for each capsule. This will show whether blake3 is being called on different bytes than what's embedded.
2. Bisect: temporarily change the kernel to spawn ONE capsule at a time (no others compiled in), confirm if single-capsule boot is deterministic. If yes → race/state bleed between capsules. If no → the verifier itself has a bug for that one capsule.
3. Audit `src/security/capsule_manifest/verify/payload.rs` and `cert_binding.rs` for any shared mutable state (statics, globals, lazy_init, etc.).
4. Run the kernel under MIRI or a sanitizer if possible.
5. Compare the no_std blake3 ("pure" feature) against the std blake3 — produce a test vector that hashes the entropy ELF on both sides.

## Status of the ceremony itself

The trust ceremony from Tasks 1-7 is **legitimate progress and worth keeping**:
- Trust-anchor pair + 34 publisher pairs are fresh and locally controlled.
- Policy + 34 cert + 34 manifest are consistent on disk.
- 0/4 boots have TA failures (previously 31/31 did).
- 18-25/31 capsules spawn cleanly each boot (previously 0/31).

The bottleneck is now the runtime verifier non-determinism, not the trust artifacts.
