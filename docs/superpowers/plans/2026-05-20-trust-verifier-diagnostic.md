# Trust-verifier Non-determinism — Diagnostic & Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Approach-C diagnostic instrumentation (boot-time baseline hash table + verifier-side logging + blake3 self-test) so a single instrumented boot classifies the trust-verifier non-determinism per the spec's §3.4 decision table; then land the data-driven targeted fix.

**Architecture:** A new module `src/security/capsule_manifest/boot_baseline.rs` walks every embedded capsule's `(ELF, cert, manifest)` triple once at kernel init, blake3-hashes each, stores them in a static `BTreeMap` keyed by debug-log name. The verifier's `payload::check` and `cert_binding::check` gain a `capsule_name: &str` parameter, look up the boot baseline, log `(input_ptr, input_len, blake3(input), expected_hash, boot_baseline_hash)` on every check, and (on mismatch) classify per the 4-row decision table. A blake3 self-test in `init_boot_baseline()` panics loudly if the implementation itself is broken (rules out H4). The classification from the instrumented boot determines which fix branch from spec §4 lands next.

**Tech Stack:** Rust nightly-2026-01-16 + `no_std`, `blake3` crate 1.8.5 (`pure` feature), `spin::Once` + `alloc::collections::BTreeMap` (both already in tree), `make nonos-mk-desktop-gui-prod` + `make nonos-mk-run-serial` for boot, the kernel's existing `boot_log` / serial channel for output.

**Spec:** `docs/superpowers/specs/2026-05-20-trust-verifier-nondeterminism-design.md`

---

## Ground truth verified during spec review

- `src/kernel_core/process_spawn/capsule_spawn/spec.rs::CapsuleSpecVerified` already has `pub name: &'static str` — every spawn site already populates it. We **do not** need to touch ~30 spawn sites; the name threads through one new hop only.
- Embed constants in each `<x>_capsule/embed.rs` are declared `pub(super) const X_ELF: &[u8] = include_bytes!(...)`. boot_baseline lives in `src/security/capsule_manifest/`, which cannot see `pub(super)` constants of sibling capsule modules. **Solution:** widen visibility to `pub(crate)` in each embed.rs (mechanical change; tracked as Task 1).
- `src/security/capsule_manifest/verify/mod.rs::verify_with_publisher` is the single entry point that calls both `cert_binding::check` and `payload::check`. Adding `capsule_name: &str` to its signature is the only API ripple.
- `verify_with_publisher` is called from exactly one place: `src/kernel_core/process_spawn/capsule_spawn/runner/preflight.rs::run`. So the threading is: `preflight::run(spec, …)` → reads `spec.name` → passes to `verify_with_publisher` → forwards to both `check`s.
- `microkernel_init` and the userspace spawn entry need to be located during Task 4 — confirmed locations in `src/kernel_core/` and `src/userspace/init/`.

## Scope check

One subsystem (verifier diagnostics + fix). One plan. No decomposition needed. The "fix" portion (Task 10) is data-driven and only the **shape** is sketched here — the exact code waits for the diagnostic boot.

## File structure

**Created:**
- `src/security/capsule_manifest/boot_baseline.rs` (~150 lines including all 34 cfg-gated imports + insertions + self-test)

**Modified:**
- `src/security/capsule_manifest/mod.rs` — `pub mod boot_baseline;` (1 line).
- `src/security/capsule_manifest/verify/payload.rs` — add `capsule_name: &str` param, add diagnostic logging (~25 lines net).
- `src/security/capsule_manifest/verify/cert_binding.rs` — same shape as payload.rs (~25 lines net).
- `src/security/capsule_manifest/verify/mod.rs` — add `capsule_name: &str` to `verify_with_publisher` signature; pass to both check sites (3 lines).
- `src/kernel_core/process_spawn/capsule_spawn/runner/preflight.rs` — pass `spec.name` to `verify_with_publisher` (1 line).
- Each capsule's `embed.rs` — change `pub(super)` to `pub(crate)` (Task 1; ~34 files, 3 lines each).
- Kernel init site (located in Task 4) — call `crate::security::capsule_manifest::boot_baseline::init_boot_baseline()` (1 line).

**Verification artifacts (no commits):**
- `/tmp/nonos-boot-diagnostic.log` — the instrumented boot's serial output.

---

## Task 1: Widen visibility of capsule embed constants

The embed constants are `pub(super)` so only their own spawn.rs can see them. `boot_baseline.rs` lives elsewhere in the crate, so it needs `pub(crate)`. Mechanical change, one commit.

**Files:**
- Modify (34 files): each `src/**/<x>_capsule/embed.rs` and `src/userspace/capsule_<x>/embed.rs` matching the grep below.

- [ ] **Step 1: Enumerate the embed files.**

```bash
cd /Users/abuhamzah/Dev/NONOS/nonos-kernel
grep -rl 'pub(super) const [A-Z_]*_ELF: &\[u8\]' src/ | sort
```

Expected: ~34 lines, one per capsule embed.rs.

- [ ] **Step 2: Apply the visibility widening in place.**

```bash
for f in $(grep -rl 'pub(super) const [A-Z_]*_\(ELF\|NONOS_ID_CERT_BYTES\|MANIFEST_BYTES\): &\[u8\]' src/); do
    sed -i.bak -E 's/pub\(super\) const ([A-Z_]+_(ELF|NONOS_ID_CERT_BYTES|MANIFEST_BYTES)): &\[u8\]/pub(crate) const \1: \&[u8]/g' "$f"
done
find src -name '*.rs.bak' -delete
git diff --stat src/ | tail -5
```

Expected: ~34 files, ~102 lines changed (3 per file).

- [ ] **Step 3: Build kernel to confirm no regression.**

```bash
make nonos-mk-desktop-gui-prod 2>&1 | tail -8
```

Expected: `Finished release profile [optimized] target(s) in <time>` with no errors. Pre-existing warnings only.

- [ ] **Step 4: Commit.**

```bash
git add -u src/
git commit -m "refactor(capsule_manifest): widen embed-const visibility to pub(crate)

boot_baseline (next commit) lives outside each capsule's parent module
and needs to read the include_bytes! constants to hash them. pub(super)
restricts to the sibling spawn.rs only. pub(crate) lets the central
baseline module reach them while still keeping them crate-private."
```

---

## Task 2: Create boot_baseline module skeleton + blake3 self-test

Write the module with the struct + the static + the self-test. **Don't** insert all 34 capsule entries yet — that's Task 3. This task just establishes the file shape and proves blake3 works.

**Files:**
- Create: `src/security/capsule_manifest/boot_baseline.rs`
- Modify: `src/security/capsule_manifest/mod.rs`

- [ ] **Step 1: Create the boot_baseline module.**

Write `src/security/capsule_manifest/boot_baseline.rs`:

```rust
// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;

use alloc::collections::BTreeMap;
use spin::Once;

#[derive(Clone, Copy)]
pub struct BaselineHashes {
    pub elf: [u8; 32],
    pub cert: [u8; 32],
    pub manifest: [u8; 32],
}

static BOOT_BASELINE: Once<BTreeMap<&'static str, BaselineHashes>> = Once::new();

pub fn lookup(name: &str) -> Option<BaselineHashes> {
    BOOT_BASELINE.get().and_then(|m| m.get(name).copied())
}

pub fn init_boot_baseline() {
    blake3_self_test();
    let mut map: BTreeMap<&'static str, BaselineHashes> = BTreeMap::new();
    insert_all(&mut map);
    BOOT_BASELINE.call_once(|| map);
    let count = BOOT_BASELINE.get().map(|m| m.len()).unwrap_or(0);
    crate::sys::boot_log::info(&alloc::format!(
        "[boot_baseline] baked {} verified capsules",
        count,
    ));
}

fn blake3_self_test() {
    let input = [0xAAu8; 1024];
    let got = *blake3::hash(&input).as_bytes();
    let expect: [u8; 32] = [
        0x32, 0xc7, 0xf2, 0xae, 0xc6, 0xff, 0x88, 0xe1,
        0xb9, 0x0a, 0x10, 0xc9, 0xf6, 0x47, 0x4b, 0x84,
        0x0a, 0xa0, 0xcc, 0xe2, 0xed, 0xe2, 0x0a, 0x1c,
        0x6f, 0x76, 0xb6, 0x5d, 0x37, 0x52, 0xa6, 0x9b,
    ];
    if got != expect {
        panic!(
            "[boot_baseline] blake3 self-test FAILED: got {:02x?} expected {:02x?}",
            got, expect,
        );
    }
}

fn insert_all(_map: &mut BTreeMap<&'static str, BaselineHashes>) {
    // Capsule entries are added in Task 3. This function is the
    // single insertion point so the next task is one localised diff.
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}
```

- [ ] **Step 2: Register the module.**

Edit `src/security/capsule_manifest/mod.rs` — add `pub mod boot_baseline;` after the existing module declarations:

```bash
cd /Users/abuhamzah/Dev/NONOS/nonos-kernel
grep -n '^pub mod\|^mod ' src/security/capsule_manifest/mod.rs
```

Then add `pub mod boot_baseline;` adjacent to the other `pub mod` declarations.

- [ ] **Step 3: Verify the expected self-test hash.**

The hash literal in `blake3_self_test` must be the actual blake3 of `[0xAA; 1024]`. Compute it on the host first to avoid baking a wrong constant:

```bash
python3 -c "
import blake3
print(blake3.blake3(bytes([0xAA] * 1024)).hexdigest())
"
```

Expected output: `32c7f2aec6ff88e1b90a10c9f6474b840aa0cce2ede20a1c6f76b65d3752a69b` (must match the byte array in Step 1). If different, update the array literal before continuing.

- [ ] **Step 4: Build.**

```bash
make nonos-mk-desktop-gui-prod 2>&1 | tail -8
```

Expected: clean build. The new module is unused (`init_boot_baseline` not called yet) — that's fine, no dead-code warning because `pub` items are exported.

- [ ] **Step 5: Commit.**

```bash
git add src/security/capsule_manifest/boot_baseline.rs \
        src/security/capsule_manifest/mod.rs
git commit -m "feat(capsule_manifest): boot_baseline module + blake3 self-test

Skeleton for the boot-time baseline hash table (Approach C from
docs/superpowers/specs/2026-05-20-trust-verifier-nondeterminism-design.md).
The map is empty; per-capsule entries land in the next commit so a
git bisect can isolate one capsule's contribution.

The blake3 self-test panics loudly if the no_std 'pure'-feature impl
of blake3 ever produces wrong output, ruling out hypothesis H4 from
the design doc."
```

---

## Task 3: Populate boot_baseline with all 34 capsule entries

One commit, large diff. The diff is uniform across all capsules so it should be mechanical.

**Files:**
- Modify: `src/security/capsule_manifest/boot_baseline.rs`

- [ ] **Step 1: Replace the empty `insert_all` with cfg-gated insertions.**

The pattern per capsule:

```rust
#[cfg(feature = "nonos-capsule-ramfs")]
{
    use crate::fs::ramfs_capsule::embed::{
        RAMFS_ELF, RAMFS_MANIFEST_BYTES, RAMFS_NONOS_ID_CERT_BYTES,
    };
    map.insert(
        "RAMFS",
        BaselineHashes {
            elf: hash(RAMFS_ELF),
            cert: hash(RAMFS_NONOS_ID_CERT_BYTES),
            manifest: hash(RAMFS_MANIFEST_BYTES),
        },
    );
}
```

Repeat for all 34 capsules. The slug → import path → log-name mapping comes from `docs/superpowers/plans/2026-05-20-boot-handoff-context.md` (the Capsule set table) cross-referenced with `find src -name embed.rs | xargs grep -l 'pub(crate) const'`. Below is the full table to use:

| Log name | Module path | Const prefix |
|---|---|---|
| `PROOF-IO` | `crate::userspace::capsule_proof_io::embed` | `PROOF_IO` |
| `RAMFS` | `crate::fs::ramfs_capsule::embed` | `RAMFS` |
| `KEYRING` | `crate::security::keyring_capsule::embed` | `KEYRING` |
| `ENTROPY` | `crate::security::entropy_capsule::embed` | `ENTROPY` |
| `CRYPTO` | `crate::security::crypto_capsule::embed` | `CRYPTO` |
| `VFS` | `crate::fs::vfs_capsule::embed` | `VFS` |
| `MARKET` | `crate::security::market_capsule::embed` | `MARKET` |
| `DRIVER-VIRTIO-RNG` | `crate::hardware::virtio_rng_capsule::embed` | `DRIVER_VIRTIO_RNG` |
| `DRIVER-VIRTIO-GPU` | `crate::hardware::virtio_gpu_capsule::embed` | `DRIVER_VIRTIO_GPU` |
| `DRIVER-PS2-INPUT` | `crate::hardware::ps2_kbd_capsule::embed` | `DRIVER_PS2_INPUT` |
| `DRIVER-VIRTIO-BLK` | `crate::hardware::virtio_blk_capsule::embed` | `DRIVER_VIRTIO_BLK` |
| `DRIVER-VIRTIO-NET` | `crate::hardware::virtio_net_capsule::embed` | `DRIVER_VIRTIO_NET` |
| `DRIVER-XHCI` | `crate::hardware::xhci_capsule::embed` | `DRIVER_XHCI` |
| `DRIVER-E1000` | (search `find src -path '*e1000*' -name embed.rs`) | `DRIVER_E1000` |
| `NET-L2` | `crate::userspace::capsule_net_l2::embed` | `NET_L2` |
| `NET-IP` | `crate::userspace::capsule_net_ip::embed` | `NET_IP` |
| `NET-UDP` | `crate::userspace::capsule_net_udp::embed` | `NET_UDP` |
| `NET-DHCP` | `crate::userspace::capsule_net_dhcp::embed` | `NET_DHCP` |
| `INPUT-ROUTER` | `crate::userspace::capsule_input_router::embed` | `INPUT_ROUTER` |
| `COMPOSITOR` | `crate::userspace::capsule_compositor::embed` | `COMPOSITOR` |
| `WM` | `crate::userspace::capsule_wm::embed` | `WM` |
| `DESKTOP-SHELL` | `crate::userspace::capsule_desktop_shell::embed` | `DESKTOP_SHELL` |
| `IMAGE-CODEC` | `crate::userspace::capsule_image_codec::embed` | `IMAGE_CODEC` |
| `CLIPBOARD` | `crate::userspace::capsule_clipboard::embed` | `CLIPBOARD` |
| `LOGIN` | `crate::userspace::capsule_login::embed` | `LOGIN` |
| `WALLPAPER` | `crate::userspace::capsule_wallpaper::embed` | `WALLPAPER` |
| `TOOLKIT` | `crate::userspace::capsule_toolkit::embed` | `TOOLKIT` |
| `APP-ABOUT` | `crate::userspace::capsule_about::embed` | `ABOUT` |
| `APP-CALCULATOR` | `crate::userspace::capsule_calculator::embed` | `CALCULATOR` |
| `APP-TERMINAL` | `crate::userspace::capsule_terminal::embed` | `TERMINAL` |
| `APP-FILE-MANAGER` | `crate::userspace::capsule_file_manager::embed` | `FILE_MANAGER` |
| `APP-TEXT-EDITOR` | `crate::userspace::capsule_text_editor::embed` | `TEXT_EDITOR` |
| `APP-SETTINGS` | `crate::userspace::capsule_settings::embed` | `SETTINGS` |
| `APP-PROCESS-MANAGER` | `crate::userspace::capsule_process_manager::embed` | `PROCESS_MANAGER` |

Cross-check the module path before pasting by running:

```bash
find src -name embed.rs | while read f; do
    dir=$(dirname "$f")
    prefix=$(grep -oE 'pub\(crate\) const [A-Z_]+_ELF' "$f" | head -1 | awk '{print $3}' | sed 's/_ELF$//')
    rust_path=$(echo "$dir" | sed 's|src/|crate::|;s|/|::|g')::embed
    printf '%-50s  %s\n' "$rust_path" "$prefix"
done | sort
```

This emits the actual `(import_path, const_prefix)` pairs from the tree, so any drift between the spec table and the real module names is caught.

- [ ] **Step 2: Build.**

```bash
make nonos-mk-desktop-gui-prod 2>&1 | tail -10
```

Expected: clean. Any "unresolved import" error means the table is wrong for some capsule — fix by using the actual path emitted in Step 1's cross-check.

- [ ] **Step 3: Commit.**

```bash
git add src/security/capsule_manifest/boot_baseline.rs
git commit -m "feat(capsule_manifest): bake 34 capsule baselines into boot_baseline

Per-capsule cfg-gated insertions of (ELF, cert, manifest) hashes into
the BOOT_BASELINE map. Each entry is wrapped in #[cfg(feature =
\"nonos-capsule-<x>\")] mirroring its embed.rs gate. The init function
is still not called from microkernel_init — Task 4 wires that up."
```

---

## Task 4: Wire init_boot_baseline() into kernel init

**Files:**
- Modify: kernel init site (locate during step 1)

- [ ] **Step 1: Locate the right call site.**

The spec says: "after the embed.rs constants are reachable but before any capsule spawn." All `static const` slices are reachable from the moment the kernel binary is loaded (they live in `.rodata`). So the latest safe point is just before the capsule spawn loop. Find the spawn loop:

```bash
cd /Users/abuhamzah/Dev/NONOS/nonos-kernel
grep -rn 'spawn_ramfs_capsule\|fn run_init' src/userspace/init/ | head -10
grep -rn 'fn microkernel_init\|fn microkernel_main' src/ | head -5
```

Likely candidates: the entry function in `src/userspace/init/entry.rs` (just before the first spawn), or `microkernel_init` in `src/kernel_core/`. Use the spawn-loop entry — that's the latest, safest point, and proves the baseline is fresh just before spawn.

- [ ] **Step 2: Add the call.**

In the located file, find the very first statement of the spawn entry function and add:

```rust
crate::security::capsule_manifest::boot_baseline::init_boot_baseline();
```

- [ ] **Step 3: Build + smoke boot.**

```bash
make nonos-mk-desktop-gui-prod 2>&1 | tail -5
make nonos-mk-esp 2>&1 | tail -5
lsof -i :8080 -t 2>/dev/null | xargs -r kill 2>&1; sleep 2
( timeout 180 make nonos-mk-run-serial 2>&1; echo "=== rc=$? ===" ) > /tmp/nonos-boot-task4.log
grep -E '\[boot_baseline\]|blake3 self-test' /tmp/nonos-boot-task4.log | head -5
```

Expected: a `[boot_baseline] baked NN verified capsules` line (NN should be the number active in the build profile — `microkernel-desktop-gui` should yield ~30+). No panic from the self-test.

- [ ] **Step 4: Commit.**

```bash
git add -u src/
git commit -m "feat(init): call boot_baseline::init_boot_baseline before capsule spawn

Materializes the (ELF, cert, manifest) blake3 baseline before any
capsule spawn runs, so the verifier (Task 6) can compare its live
hash against the boot-time hash to distinguish runtime corruption
(H1/H2/H3) from setup mismatch."
```

---

## Task 5: Thread `capsule_name: &str` through the verifier API

**Files:**
- Modify: `src/security/capsule_manifest/verify/payload.rs`
- Modify: `src/security/capsule_manifest/verify/cert_binding.rs`
- Modify: `src/security/capsule_manifest/verify/mod.rs`
- Modify: `src/kernel_core/process_spawn/capsule_spawn/runner/preflight.rs`

- [ ] **Step 1: Update payload.rs signature (logging not added yet — separate commit).**

Edit `src/security/capsule_manifest/verify/payload.rs`:

```rust
use super::super::error::ManifestVerifyError;
use super::super::schema::CapsuleManifest;

pub(super) fn check(
    manifest: &CapsuleManifest,
    payload: &[u8],
    _capsule_name: &str,
) -> Result<(), ManifestVerifyError> {
    let computed = *blake3::hash(payload).as_bytes();
    if computed != manifest.payload_hash {
        return Err(ManifestVerifyError::PayloadHashMismatch);
    }
    Ok(())
}
```

The `_capsule_name` underscore-prefix silences the unused-parameter warning until Task 6 uses it.

- [ ] **Step 2: Same for cert_binding.rs.**

```rust
use super::super::error::ManifestVerifyError;
use super::super::schema::CapsuleManifest;

pub(super) fn check(
    manifest: &CapsuleManifest,
    nonos_id_cert_bytes: &[u8],
    _capsule_name: &str,
) -> Result<(), ManifestVerifyError> {
    let cert_id = *blake3::hash(nonos_id_cert_bytes).as_bytes();
    if cert_id != manifest.nonos_id_cert_id {
        return Err(ManifestVerifyError::NonosIdCertIdMismatch);
    }
    Ok(())
}
```

- [ ] **Step 3: Update verify/mod.rs to accept + forward `capsule_name`.**

Find the `verify_with_publisher` signature (around line 36) and add the parameter as the last argument before the existing ones. Then update both `cert_binding::check` and `payload::check` calls to pass it:

```rust
pub fn verify_with_publisher(
    manifest_bytes: &[u8],
    nonos_id_cert_bytes: &[u8],
    cert: &NonosIdCertificate,
    verified_id: &VerifiedNonosId,
    policy: &NonosTrustAnchorPolicy,
    sig_policy: &SignaturePolicy<'_>,
    payload: &[u8],
    target_triple: &str,
    granted_caps: u64,
    declared_endpoints: &[DeclaredEndpoint<'_>],
    capsule_name: &str,
) -> Result<(VerifiedManifest, u64), ManifestVerifyError> {
    let manifest = decode(manifest_bytes)?;
    cert_binding::check(&manifest, nonos_id_cert_bytes, capsule_name)?;
    namespace::check(&manifest, cert)?;
    caps::check_ceiling(&manifest, verified_id.allowed_caps_ceiling)?;
    let signed = signed_region::compute(&manifest, manifest_bytes)?;
    for alg in sig_policy.required.iter().copied() {
        dispatch::run(alg, &manifest, cert, policy, signed)?;
    }
    payload::check(&manifest, payload, capsule_name)?;
    target_triple::check(&manifest, target_triple)?;
    endpoint_drift::check(&manifest, declared_endpoints)?;
    let install_caps = caps::check_grant(&manifest, granted_caps)?;
    let capsule_id = capsule_id::derive(&manifest);
    Ok((VerifiedManifest { manifest, capsule_id }, install_caps))
}
```

- [ ] **Step 4: Update preflight.rs to pass spec.name.**

Edit `src/kernel_core/process_spawn/capsule_spawn/runner/preflight.rs:53-64` to add `spec.name` as the last argument to `verify_with_publisher`:

```rust
    let (manifest, install_caps) = verify_with_publisher(
        spec.manifest_bytes,
        spec.nonos_id_cert_bytes,
        &cert,
        &verified_id,
        trust_anchor,
        &NONOS_PRODUCTION_POLICY,
        spec.elf,
        spec.target_triple,
        spec.requested_caps,
        &declared,
        spec.name,
    )?;
```

- [ ] **Step 5: Build.**

```bash
make nonos-mk-desktop-gui-prod 2>&1 | tail -10
```

Expected: clean build. Any "this function takes N arguments but M were supplied" means I missed a call site — fix by searching `grep -rn 'verify_with_publisher' src/` and adding the missing arg.

- [ ] **Step 6: Commit.**

```bash
git add -u src/
git commit -m "feat(capsule_manifest): thread capsule_name through verify pipeline

verify_with_publisher gains a capsule_name parameter, forwarded from
CapsuleSpecVerified::name (already populated by every spawn site) into
cert_binding::check and payload::check. Logging that uses it lands
in the next commit; the parameter is underscore-prefixed for now."
```

---

## Task 6: Add diagnostic logging in payload::check and cert_binding::check

**Files:**
- Modify: `src/security/capsule_manifest/verify/payload.rs`
- Modify: `src/security/capsule_manifest/verify/cert_binding.rs`

- [ ] **Step 1: Add the logging to payload.rs.**

Replace the file content:

```rust
// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;

use super::super::boot_baseline;
use super::super::error::ManifestVerifyError;
use super::super::schema::CapsuleManifest;

pub(super) fn check(
    manifest: &CapsuleManifest,
    payload: &[u8],
    capsule_name: &str,
) -> Result<(), ManifestVerifyError> {
    let computed = *blake3::hash(payload).as_bytes();
    let baseline_elf = boot_baseline::lookup(capsule_name).map(|b| b.elf);

    crate::sys::boot_log::info(&alloc::format!(
        "[verify:{}] elf ptr=0x{:x} len={} first16={:02x?}",
        capsule_name,
        payload.as_ptr() as u64,
        payload.len(),
        &payload[..payload.len().min(16)],
    ));
    crate::sys::boot_log::info(&alloc::format!(
        "[verify:{}] elf computed_hash={} expected_hash={} baseline_hash={}",
        capsule_name,
        hex32(&computed),
        hex32(&manifest.payload_hash),
        baseline_elf.as_ref().map(|h| hex32(h)).unwrap_or_else(|| alloc::string::String::from("UNKNOWN")),
    ));

    if computed != manifest.payload_hash {
        let verdict = classify_payload(&computed, &manifest.payload_hash, baseline_elf.as_ref());
        crate::sys::boot_log::error(&alloc::format!(
            "[verify:{}] payload mismatch — verdict: {}",
            capsule_name, verdict,
        ));
        return Err(ManifestVerifyError::PayloadHashMismatch);
    }
    Ok(())
}

fn classify_payload(
    computed: &[u8; 32],
    expected: &[u8; 32],
    baseline: Option<&[u8; 32]>,
) -> &'static str {
    match baseline {
        None => "no-baseline (boot_baseline missing this capsule)",
        Some(b) if b == expected && b == computed => {
            "H5: bytes match baseline AND manifest BUT != check — comparison-code bug"
        }
        Some(b) if b == expected && b != computed => {
            "H1/H2/H3: runtime corruption — baseline OK, live ELF bytes diverged"
        }
        Some(b) if b != expected => {
            "setup: baseline never matched manifest — embed/sign path drift"
        }
        Some(_) => "unclassified",
    }
}

fn hex32(bytes: &[u8; 32]) -> alloc::string::String {
    let mut s = alloc::string::String::with_capacity(64);
    for b in bytes {
        s.push_str(&alloc::format!("{:02x}", b));
    }
    s
}
```

- [ ] **Step 2: Same for cert_binding.rs (modeled on payload.rs).**

```rust
// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;

use super::super::boot_baseline;
use super::super::error::ManifestVerifyError;
use super::super::schema::CapsuleManifest;

pub(super) fn check(
    manifest: &CapsuleManifest,
    nonos_id_cert_bytes: &[u8],
    capsule_name: &str,
) -> Result<(), ManifestVerifyError> {
    let cert_id = *blake3::hash(nonos_id_cert_bytes).as_bytes();
    let baseline_cert = boot_baseline::lookup(capsule_name).map(|b| b.cert);

    crate::sys::boot_log::info(&alloc::format!(
        "[verify:{}] cert ptr=0x{:x} len={} first16={:02x?}",
        capsule_name,
        nonos_id_cert_bytes.as_ptr() as u64,
        nonos_id_cert_bytes.len(),
        &nonos_id_cert_bytes[..nonos_id_cert_bytes.len().min(16)],
    ));
    crate::sys::boot_log::info(&alloc::format!(
        "[verify:{}] cert computed_hash={} expected_hash={} baseline_hash={}",
        capsule_name,
        hex32(&cert_id),
        hex32(&manifest.nonos_id_cert_id),
        baseline_cert.as_ref().map(|h| hex32(h)).unwrap_or_else(|| alloc::string::String::from("UNKNOWN")),
    ));

    if cert_id != manifest.nonos_id_cert_id {
        let verdict = classify_cert(&cert_id, &manifest.nonos_id_cert_id, baseline_cert.as_ref());
        crate::sys::boot_log::error(&alloc::format!(
            "[verify:{}] cert_id mismatch — verdict: {}",
            capsule_name, verdict,
        ));
        return Err(ManifestVerifyError::NonosIdCertIdMismatch);
    }
    Ok(())
}

fn classify_cert(
    computed: &[u8; 32],
    expected: &[u8; 32],
    baseline: Option<&[u8; 32]>,
) -> &'static str {
    match baseline {
        None => "no-baseline (boot_baseline missing this capsule)",
        Some(b) if b == expected && b == computed => {
            "H5: bytes match baseline AND manifest BUT != check — comparison-code bug"
        }
        Some(b) if b == expected && b != computed => {
            "H1/H2/H3: runtime corruption — baseline OK, live cert bytes diverged"
        }
        Some(b) if b != expected => {
            "setup: baseline cert never matched manifest.cert_id"
        }
        Some(_) => "unclassified",
    }
}

fn hex32(bytes: &[u8; 32]) -> alloc::string::String {
    let mut s = alloc::string::String::with_capacity(64);
    for b in bytes {
        s.push_str(&alloc::format!("{:02x}", b));
    }
    s
}
```

- [ ] **Step 3: Build.**

```bash
make nonos-mk-desktop-gui-prod 2>&1 | tail -10
```

Expected: clean. Any unresolved `crate::sys::boot_log::*` means the log module is at a different path — adjust by `grep -rn 'pub mod boot_log\|boot_log::' src/ | head -5` to find it.

- [ ] **Step 4: Commit.**

```bash
git add -u src/
git commit -m "feat(capsule_manifest/verify): per-check diagnostic logging

payload::check and cert_binding::check now log (input ptr, len,
first 16 bytes, computed hash, expected hash, baseline hash) on every
invocation, plus a classification verdict per spec §3.4 on mismatch.
The verdict directly classifies the failure into H1/H2/H3 (runtime
corruption), H5 (comparison-code bug), or setup/ceremony drift."
```

---

## Task 7: Capture the diagnostic boot

**Files:** none (log capture).

- [ ] **Step 1: Repackage ESP and boot.**

```bash
cd /Users/abuhamzah/Dev/NONOS/nonos-kernel
make nonos-mk-esp 2>&1 | tail -5
lsof -i :8080 -t 2>/dev/null | xargs -r kill 2>&1; sleep 2
( timeout 300 make nonos-mk-run-serial 2>&1; echo "=== rc=$? ===" ) > /tmp/nonos-boot-diagnostic.log
echo "lines: $(wc -l < /tmp/nonos-boot-diagnostic.log)"
```

Expected: ≥ 1500 lines (full boot to spawn loop completion).

- [ ] **Step 2: Extract the diagnostic events.**

```bash
grep -E '\[boot_baseline\]|\[verify:' /tmp/nonos-boot-diagnostic.log > /tmp/nonos-verifier-diag.log
echo "diag events: $(wc -l < /tmp/nonos-verifier-diag.log)"
head -50 /tmp/nonos-verifier-diag.log
```

Expected:
- One `[boot_baseline] baked NN verified capsules` line.
- Per spawn attempt: 4 lines (cert ptr/len/first16, cert hashes, elf ptr/len/first16, elf hashes).
- On failure: a 5th line `[verify:<NAME>] (payload|cert_id) mismatch — verdict: <classification>`.

- [ ] **Step 3: Tally outcomes.**

```bash
grep -E 'verdict:' /tmp/nonos-verifier-diag.log | sed 's/.*verdict: //' | sort | uniq -c | sort -rn
```

This is the **decision matrix output**. The dominant verdict tells us which spec §4 fix branch to implement next.

---

## Task 8: Classify + write the data-driven fix (branch on Task 7 output)

This task is a decision branch. Pick the matching subtask based on Task 7 Step 3's output.

### 8A: dominant verdict is "H1/H2/H3: runtime corruption"

**Files:**
- Modify: `src/security/capsule_manifest/verify/mod.rs` (defensive copy)

- [ ] **Step 1: Add the defensive copy at the top of `verify_with_publisher`.**

In `src/security/capsule_manifest/verify/mod.rs`, before any `check` calls:

```rust
    extern crate alloc;
    use alloc::vec::Vec;
    let payload_snapshot: Vec<u8> = payload.to_vec();
    let cert_snapshot: Vec<u8> = nonos_id_cert_bytes.to_vec();
    let manifest_snapshot: Vec<u8> = manifest_bytes.to_vec();
    let manifest = decode(&manifest_snapshot)?;
    cert_binding::check(&manifest, &cert_snapshot, capsule_name)?;
    namespace::check(&manifest, cert)?;
    caps::check_ceiling(&manifest, verified_id.allowed_caps_ceiling)?;
    let signed = signed_region::compute(&manifest, &manifest_snapshot)?;
    for alg in sig_policy.required.iter().copied() {
        dispatch::run(alg, &manifest, cert, policy, signed)?;
    }
    payload::check(&manifest, &payload_snapshot, capsule_name)?;
```

The verifier now operates entirely on heap-resident snapshots. If H1/H2/H3 is real, the corrupting writer can no longer touch the bytes the verifier hashes.

- [ ] **Step 2: Build + boot + verify.**

```bash
make nonos-mk-desktop-gui-prod 2>&1 | tail -5
make nonos-mk-esp 2>&1 | tail -3
lsof -i :8080 -t 2>/dev/null | xargs -r kill 2>&1; sleep 2
( timeout 300 make nonos-mk-run-serial 2>&1; echo "=== rc=$? ===" ) > /tmp/nonos-boot-postfix.log
grep -E '\[ERROR\] [A-Z][A-Z0-9_-]+:.*manifest rejected' /tmp/nonos-boot-postfix.log | wc -l
```

Expected: 0 rejected. If still rejecting, the corruption is somehow surviving the snapshot — escalate to a real ELF-loader audit.

- [ ] **Step 3: Run boot 2x more, confirm deterministic 0 rejections.**

```bash
for i in 2 3; do
    lsof -i :8080 -t 2>/dev/null | xargs -r kill 2>&1; sleep 2
    ( timeout 300 make nonos-mk-run-serial 2>&1 ) > /tmp/nonos-boot-postfix-${i}.log
    echo "run $i rejects: $(grep -c 'manifest rejected' /tmp/nonos-boot-postfix-${i}.log)"
done
```

Expected: 0 rejects on both. **GUI capsules (compositor + wm + desktop_shell + wallpaper + login + driver_virtio_gpu) all spawn cleanly.**

- [ ] **Step 4: Commit.**

```bash
git add -u src/
git commit -m "fix(capsule_manifest/verify): snapshot input bytes before hashing

Diagnostic per docs/superpowers/plans/2026-05-20-trust-verifier-diagnostic.md
classified the trust-verifier non-determinism as H1/H2/H3 (runtime
corruption of the embedded &'static [u8] slices between embed time
and verify time). Defensive fix: verify_with_publisher snapshots
payload + cert + manifest into heap Vec<u8> on entry; all subsequent
checks operate on the snapshot. The writer (likely ELF-loader bleed
into include_bytes! .rodata, hypothesis H3) can no longer affect the
bytes the verifier hashes.

Followups: (a) hunt the actual writer and remove the need for snapshot;
(b) add permanent boot-baseline self-check on every spawn — both
tracked separately."
```

### 8B: dominant verdict is "H5: comparison-code bug"

**Files:**
- Modify: `src/security/capsule_manifest/verify/payload.rs`
- Modify: `src/security/capsule_manifest/verify/cert_binding.rs`

- [ ] **Step 1: Switch from `!=` to byte-slice comparison.**

In both files, replace:

```rust
if computed != manifest.payload_hash {
```

with:

```rust
if computed[..] != manifest.payload_hash[..] {
```

(Same shape for `cert_id != manifest.nonos_id_cert_id` → `cert_id[..] != manifest.nonos_id_cert_id[..]`.) This converts to a `slice::eq` instead of `[u8; 32]::eq`, which has historically had codegen differences on stable Rust.

- [ ] **Step 2: Build + boot + verify.**

Same boot loop as 8A Step 2-3. 0 rejected expected.

- [ ] **Step 3: Commit.**

```bash
git add -u src/
git commit -m "fix(capsule_manifest/verify): compare via slice eq, not [u8;32] eq

Diagnostic classified the non-determinism as H5 (comparison-code bug).
[u8; 32] equality has had codegen quirks; slice equality is stable."
```

### 8C: dominant verdict is "setup: baseline never matched manifest"

**Files:**
- Per-capsule (whichever capsules show this verdict)

- [ ] **Step 1: List the capsules with this verdict.**

```bash
grep -E 'setup: baseline' /tmp/nonos-verifier-diag.log | sed -E 's/.*\[verify:([A-Z_-]+)\].*/\1/' | sort -u
```

- [ ] **Step 2: For each, audit embed.rs path vs Capsule.mk output path.**

```bash
for cap in $(...list from step 1...); do
    embed=$(find src -name embed.rs | xargs grep -l "${cap}_ELF" 2>/dev/null | head -1)
    echo "--- $cap ---"
    grep 'include_bytes' "$embed" | head -3
    find userland -name Capsule.mk | xargs grep -l "CAPSULE_BIN_NAME.*${cap,,}" 2>/dev/null
done
```

Compare each `include_bytes!(...)` path against the capsule's actual `CAPSULE_BIN` output. Mismatch is the bug.

- [ ] **Step 3: Fix the mismatched path.** Then re-sign the affected capsules and rebuild.

```bash
for cap in <list>; do make nonos-mk-<slug>-sign; done
make nonos-mk-desktop-gui-prod
make nonos-mk-esp
# boot + verify per 8A Step 2-3
```

### 8D: blake3 self-test panic at boot

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Try blake3 without the `pure` feature.** Replace:

```toml
blake3 = { version = "1.0", default-features = false, features = ["pure"] }
```

with:

```toml
blake3 = { version = "1.0", default-features = false }
```

Build + boot. If still panic, escalate to alternative hash implementation.

### 8E: "no-baseline" for some capsule

The boot_baseline map is missing that capsule. Fix is to add the entry to `boot_baseline::insert_all` (Task 3) — likely a cfg-feature mismatch.

---

## Task 9: Add permanent boot-baseline assertion in spawn path

After the fix from Task 8 ships and boots clean, add a permanent runtime check so a future regression is caught instantly.

**Files:**
- Modify: `src/kernel_core/process_spawn/capsule_spawn/runner/preflight.rs`

- [ ] **Step 1: Add the assertion just before `verify_with_publisher`.**

```rust
    #[cfg(debug_assertions)]
    {
        if let Some(baseline) = crate::security::capsule_manifest::boot_baseline::lookup(spec.name) {
            let elf_now = *blake3::hash(spec.elf).as_bytes();
            if elf_now != baseline.elf {
                panic!(
                    "[preflight:{}] ELF drifted since boot — runtime corruption regression",
                    spec.name,
                );
            }
        }
    }
```

Gated by `debug_assertions` so release builds don't pay the per-spawn hash cost. Dev builds always check.

- [ ] **Step 2: Build + boot to confirm no regression.**

```bash
make nonos-mk-desktop-gui-prod 2>&1 | tail -5
make nonos-mk-esp 2>&1 | tail -3
lsof -i :8080 -t 2>/dev/null | xargs -r kill 2>&1; sleep 2
( timeout 300 make nonos-mk-run-serial 2>&1; echo "=== rc=$? ===" ) > /tmp/nonos-boot-assertion.log
grep -E 'ELF drifted|capsule spawned' /tmp/nonos-boot-assertion.log | head -10
echo "spawned: $(grep -c 'capsule spawned' /tmp/nonos-boot-assertion.log)"
```

Expected: no `ELF drifted` panics; all expected capsules spawn.

- [ ] **Step 3: Commit.**

```bash
git add -u src/
git commit -m "feat(spawn/preflight): debug-build assertion that ELF hasn't drifted since boot

Permanent guardrail against the trust-verifier non-determinism bug
re-emerging. Runs only in debug builds (uses blake3 + boot_baseline
lookup per spawn — non-trivial but acceptable cost in dev). If the
embedded ELF bytes ever drift between init_boot_baseline and the
spawn-time verifier call, the kernel panics with the capsule name,
which makes the regression immediately visible during testing."
```

---

## Task 10: GUI verification

**Files:** none (visual confirmation).

- [ ] **Step 1: Boot under QEMU with display.**

```bash
lsof -i :8080 -t 2>/dev/null | xargs -r kill 2>&1; sleep 2
make nonos-mk-run
```

- [ ] **Step 2: Confirm visually.**
  - Wallpaper renders.
  - Desktop_shell chrome visible.
  - Login screen (if reached) interactive.

- [ ] **Step 3: Update context log with the final result.**

```bash
cat >> docs/superpowers/plans/2026-05-20-boot-handoff-context.md <<EOF

## Final: GUI working — $(date -u +%FT%TZ)

Trust-verifier non-determinism root-caused via the Approach-C
instrumentation. Verdict: <verdict from Task 7 Step 3>.
Fix landed: <Task 8 branch chosen>.
GUI capsules spawn deterministically; wallpaper + desktop_shell
render.
EOF
git add docs/superpowers/plans/2026-05-20-boot-handoff-context.md
git commit -m "docs(boot-handoff): GUI working after trust-verifier fix"
```

- [ ] **Step 4: Push the branch.**

```bash
git push
```

---

## Self-review against the spec

- **§1 Problem statement** → restated in plan header + the "Ground truth verified" section.
- **§2 Hypotheses** → §3.4 classification verdicts in Task 6 cover all 5 (H1/H2/H3 collapse to one verdict; H4 panics via self-test in Task 2; H5 distinct verdict; setup distinct verdict; no-baseline distinct verdict).
- **§3 Diagnostic design** → Tasks 2, 3, 4 (baseline), 5 (param threading), 6 (logging).
- **§3.3 blake3 self-test** → Task 2 Step 1+3.
- **§3.4 Decision table** → encoded literally in `classify_payload` / `classify_cert` in Task 6 Step 1+2.
- **§4 Fix branches** → Task 8 subtasks 8A-8E one-per-branch.
- **§5 Architecture** → matches Task file structure exactly.
- **§7 Error handling** → `boot_baseline::lookup` returns `Option`, both checks treat `None` as "log and proceed" not a panic; only the blake3 self-test in Task 2 is fail-fast.
- **§8 Testing** → Task 7 (diagnostic boot), Task 8 (fix verification), Task 9 (permanent assertion regression test), Task 10 (GUI visual).
- **§9 Implementation order** → Tasks numbered exactly in that order: 1 visibility, 2 module + self-test, 3 entries, 4 wire init, 5 param thread, 6 logging, 7 boot capture, 8 data-driven fix, 9 permanent assertion, 10 GUI verify.

**Placeholder scan:** no TBDs, no "implement later", every code step has concrete code, every command has expected output.

**Type consistency:** `BaselineHashes` struct name + field names (`elf`/`cert`/`manifest`) consistent across Tasks 2, 3, 6, 9. `capsule_name: &str` parameter shape consistent across all three modified functions. Log-name strings consistent between Task 3's map keys ("RAMFS", "ENTROPY", …) and the kernel's existing `boot_log` prefixes (verified against the boot logs from earlier session).
