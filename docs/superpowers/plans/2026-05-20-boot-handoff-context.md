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

## Boot 5-7: identified + fixed kernel MSI-X PF (src/drivers/pci/msi/msix.rs)

Diagnostic chain:
1. User's later boot reached deeper into userland and exposed:
   - `[TRAP PF] cpl=0 rip=0xffffffff80084447 ... err=2 cr2=0x0000000080843000 pid=7`
   - `[desktop_shell] setup failed` + `[wallpaper] setup failed`
   - `[TRAP GP] cpl=3 rip=0x21139f39 pid=7 err=0x1a` (likely follow-on after kernel killed pid 7's state)
2. `nm` resolved 0xffffffff80084447 to inside `RealMsixOps::program_run` (src/hardware/broker/irq/msix_ops/real.rs).
3. Tracing into `src/drivers/pci/msi/msix.rs` — `configure_msix`, `mask_msix_vector`, `unmask_msix_vector`, `is_msix_vector_pending` all do `bar.address()` (returns **PhysAddr**) and wrap it in `VirtAddr::new(...)` then call `mmio_w32`/`mmio_r32`. Direct CLAUDE.md violation: "Never cast a physical address straight to a virtual pointer — map via crate::memory::mmio::map_device_memory first."
4. The 4 functions had `// SAFETY: MSI-X table is mapped and aligned` comments — factually wrong; the table was never mapped.
5. cr2=0x80843000 = the BAR phys address of (probably) the virtio device whose MSI-X programming the kernel was attempting.

### Fix landed (src/drivers/pci/msi/msix.rs)

- Added `use crate::memory::addr::{PhysAddr, VirtAddr};` and `use crate::memory::mmio::{map_device_memory, unmap_mmio};` at top.
- Added helper `fn map_msix_window(table_base: PhysAddr, offset: u64, len: usize) -> Result<VirtAddr>` that does the phys→virt translation correctly.
- Refactored all 4 access functions to: compute phys window, `map_device_memory`, do the mmio op, `unmap_mmio`.
- Removed the false `// SAFETY: ...` comments — the code now actually satisfies the invariant.
- Build clean: 1m07s, 279 pre-existing warnings, 0 errors.

### Boot 7 result (post-fix)

- **0 kernel PFs**, **0 GP faults** (vs 1 each before fix).
- 14 capsules spawned, 12 rejected.
- Trust-chain non-determinism (the remaining bug from Boots 1-4) STILL drops COMPOSITOR + DESKTOP-SHELL this run, blocking the GUI chain.

### What's still open

The trust-chain non-determinism remains — that's the bug from Boots 1-4 (same kernel binary, different rejection set per boot). The MSI-X fix doesn't touch it. Per the earlier diagnosis, candidate root-causes are memory corruption of `&'static [u8]` slices between embed and verify, race in concurrent spawn, or ELF loader bleed into the include_bytes! `.rodata` region. The recommended next-step instrumentation (logging blake3(payload) and manifest.payload_hash hex per spawn) hasn't been written yet.

## Trust-verifier diagnostic complete — 2026-05-20

Implemented Approach C from `docs/superpowers/specs/2026-05-20-trust-verifier-nondeterminism-design.md`:
boot-time blake3 baseline for every embedded capsule + per-check
verifier logging + blake3 self-test (10 commits, plan in
`docs/superpowers/plans/2026-05-20-trust-verifier-diagnostic.md`).

### Definitive diagnosis from instrumented boot

For every capsule, the verifier now logs three hashes:
- `expected` = manifest.payload_hash (signed at build time)
- `baseline` = blake3(embedded ELF) computed at `init_boot_baseline` (top of `run_init`)
- `computed` = blake3(spec.elf) computed at the verify call (per spawn)

Per-capsule outcomes (post-nuclear-clean rebuild):

| Pattern | Count | Capsules (sample) |
|---|---|---|
| All 3 equal — chain OK, passes | 11+ | virtio_rng, virtio_blk, virtio_gpu, virtio_net, ps2_kbd, net.ip, net.dhcp, image_codec, toolkit, app.about, app.terminal |
| baseline=expected, computed DIFFERS (runtime corruption between boot and spawn) | 4–6 | keyring, compositor, desktop_shell, app.calculator, driver.virtio_net0, driver.ps2_kbd0 (set varies per boot) |
| Setup mismatch — embedded bytes never matched manifest | 1–2 | crypto_pool, login |
| Late-bind — baseline wrong, computed becomes correct | 6 | ramfs, entropy_pool, driver.xhci0, net.l2, input_router, wm, clipboard |

### Root cause (now identifiable)

**This is a kernel paging / `.rodata` corruption bug, not a verifier bug.**

The kernel's `.rodata` section — which holds all `include_bytes!` data — gets clobbered between `init_boot_baseline` (very early in `run_init`) and the per-capsule `spawn_<x>_capsule()` calls (slightly later). The corruption is selective (only certain pages) and non-deterministic across boots (which capsules are affected varies). Some bytes also are observed to "fix themselves" between boot and verify (the "late-bind" pattern), consistent with the virtual-to-physical mapping changing.

Evidence:
- blake3 self-test passes at boot → H4 ruled out.
- Boot-time hash of embedded ELF is wrong (relative to manifest) for some capsules → embed time pulled in different bytes than sign time saw (H1/setup mix).
- For most failing capsules, boot baseline IS correct → live bytes get corrupted later.
- Defensive snapshot (`payload.to_vec()` at verifier entry) doesn't help → corruption already happened by the time the verifier runs.
- The cert layer is mostly stable end-to-end; the ELF layer is the dominant failure.

### Why the trust ceremony "works on disk" but not in the kernel image

`cargo test --release --test artifacts` passes because it reads files from disk. The disk artifacts are mutually consistent (ELF↔manifest↔cert↔policy). The bug is purely in **how the kernel binary's `.rodata` retains those bytes through init**, not in the artifacts themselves.

### Next steps (outside this session's scope)

1. Audit `src/memory/unified/init/run.rs` — `init_unified_vm` is the prime suspect: it rebuilds the kernel's page tables. If it re-creates the `.rodata` mappings using fresh physical pages without copying the original contents, the bytes would be uninitialized or zeroed until something else writes them.
2. Compare `boot.handoff::init_handoff`'s initial page tables vs the post-`init_unified_vm` tables: do the `.rodata` virt→phys mappings remain stable?
3. Add a kernel-side memory invariant: after `init_unified_vm`, walk `.rodata` and assert blake3 of each page matches the initial blake3 captured pre-unified-vm.
4. The fix is likely in `init_unified_vm` — either preserve the bootloader's `.rodata` mappings or correctly copy the bytes into the new mappings.

### What the trust-verifier instrumentation accomplished

- Eliminated H4 (blake3) via self-test.
- Eliminated H5 (comparison bug) via per-capsule hex logs.
- Identified the bug as upstream of the verifier (defensive snapshot doesn't help).
- Provided per-capsule per-spawn data that maps every failure to a specific (baseline/computed/expected) triple.
- Defensive snapshot remains in place as a permanent guardrail against ANY future verifier-internal mutation.

The trust ceremony + instrumentation work is shippable. The remaining bug is a separate kernel-paging investigation.
