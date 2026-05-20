# Trust-verifier Non-Determinism — Diagnostic & Fix Design

**Status:** Approved (brainstorm transcript: 2026-05-20)
**Author:** root-cause investigation
**Predecessors:**
- [docs/superpowers/plans/2026-05-20-boot-handoff-trust-ceremony.md](../plans/2026-05-20-boot-handoff-trust-ceremony.md)
- [docs/superpowers/plans/2026-05-20-boot-handoff-context.md](../plans/2026-05-20-boot-handoff-context.md)

**Out of scope:** the trust ceremony (already shipped, commit `99c456bc6`). The MSI-X phys-as-virt PF (already shipped, commit `4f4e8c9d3`). Adding capsules to the verified set. Refactoring the manifest schema.

---

## 1. Problem statement

The kernel's capsule manifest verifier rejects a **non-deterministic subset** of capsules on every boot, even with a byte-identical `target/kernel_attested.bin` and an unchanged on-disk trust set. Boot 3 and Boot 4 in `2026-05-20-boot-handoff-context.md` used the same kernel binary (sha256 `e7c64b38…`); Boot 3 rejected 13 capsules, Boot 4 rejected 9, and the intersection was only {RAMFS, CRYPTO, LOGIN}.

### What is verified true

- The on-disk chain is mathematically consistent: `cargo test --release --test artifacts` (which decodes the policy and verifies `cert + manifest + ELF` for every entry in `nonos-sign/tests/artifacts.rs` `VERIFIED`) returns `ok` — i.e. for every capsule, `blake3(on-disk ELF) == manifest.payload_hash` and `blake3(on-disk cert) == manifest.nonos_id_cert_id`.
- The kernel binary contains the on-disk ELF, cert, and manifest **byte-for-byte at exactly one location each** (verified via python `find` + `sha256` of the embedded entropy ELF: `sha256 = on-disk sha256`, byte-equal).
- Signer and kernel both use `blake3` crate version `1.8.5` (Cargo.lock pinning, identical hashing primitive).
- The manifest decoder reads `payload_hash` at the correct offset (validated against hex dump: `db87299c…` matches `blake3(entropy ELF)`).
- The verifier code path is `payload::check`: `if *blake3::hash(payload).as_bytes() != manifest.payload_hash { return Err(PayloadHashMismatch) }`.

### What is true but unexplained

Despite all the above, the kernel rejects a different subset of capsules each boot.

## 2. Candidate root causes (the hypothesis set)

| # | Hypothesis | Mechanism | Bench signal |
|---|---|---|---|
| H1 | **Runtime memory corruption** of the embedded `&'static [u8]` slice | Something writes into the kernel's `.rodata` region holding the include_bytes! data between embed time (compile) and verify time (spawn). | `blake3(slice_at_boot) == manifest.payload_hash` but `blake3(slice_at_verify) != boot baseline`. |
| H2 | **Spawn race / shared mutable state** | Two capsule spawns interleave; the verifier reads from a buffer that another spawn is mutating, or shares an Mmio mapping / scratch buffer. | Different rejection sets per boot, correlated with spawn-order-relative timing. |
| H3 | **ELF loader bleed into the include_bytes! region** | The ELF loader, when processing a capsule, applies relocations or section copies that overlap the embedded `.rodata`. | Same as H1 but the corruption is observable as a write to a specific known address range. |
| H4 | **blake3 implementation bug** in `no_std` / `pure` feature | The kernel uses `blake3 = { version = "1.0", default-features = false, features = ["pure"] }`. A buggy implementation could produce wrong hashes for specific input alignments/lengths. | A self-test of a known input at boot gives a wrong hash. |
| H5 | **Comparison-code bug** | `[u8; 32] != [u8; 32]` fires when bytes are actually equal (constant-time eq bug, alignment, etc.). | `payload_hash` and `blake3(payload)` print as identical hex but the `!=` returns true. |

H1, H2, H3 all fall in the "data is corrupted at runtime" family; H4, H5 are "data is fine but the comparison lies." A single instrumented boot needs to distinguish all five.

## 3. Diagnostic design (Approach C)

The design instruments **two points** and adds **one boot-time invariant**:

### 3.1 Boot-time baseline (new module)

At kernel init, walk every embedded capsule's `(ELF, CERT, MANIFEST)` triple and compute `blake3` of each. Store the hashes in a packed static table keyed by capsule slug.

**New file:** `src/security/capsule_manifest/boot_baseline.rs` (~120 lines including the 34 imports + 34 entries)
- `pub struct BaselineHashes { elf: [u8; 32], cert: [u8; 32], manifest: [u8; 32] }`
- `pub static BOOT_BASELINE: spin::Once<BTreeMap<&'static str, BaselineHashes>>`
- `pub fn init_boot_baseline()` — called from `microkernel_init` after the embed.rs constants are reachable but before any capsule spawn. Imports each capsule's embed module directly (e.g. `use crate::security::entropy_capsule::embed::{ENTROPY_ELF, ENTROPY_NONOS_ID_CERT_BYTES, ENTROPY_MANIFEST_BYTES};`), hashes the three slices, inserts into the map keyed by the capsule's debug-log name (e.g. `"ENTROPY"`). Each capsule is inserted only when its corresponding `#[cfg(feature = "nonos-capsule-x")]` is active — this matches how the embed.rs gates fire.
- `pub fn lookup(name: &str) -> Option<BaselineHashes>` — used by the verifier to fetch the boot-time hash for a given capsule name.

No per-capsule shim is needed; boot_baseline.rs is the single place that knows about every capsule's embed module. This trades centralization for clarity — when a new capsule is added to the verified set, it must be added here in one place, parallel to its embed.rs entry.

### 3.2 Verifier-side logging (modify)

Modify `src/security/capsule_manifest/verify/payload.rs` and `cert_binding.rs`:
- On entry, log `payload.as_ptr() as u64`, `payload.len()`, first 16 bytes of payload as hex.
- Log computed `blake3(payload)` hex.
- Log `manifest.payload_hash` hex.
- **Additionally** look up the capsule's boot baseline from `BOOT_BASELINE` (via a side channel — the verifier doesn't know the slug, so we add a `capsule_name: &str` parameter to `check`) and log `boot_baseline.elf` hex.
- On mismatch, log all three side-by-side and the verdict per §3.4.

**Delta:** ~30 lines in payload.rs, ~30 in cert_binding.rs, plus the `capsule_name` parameter threading through `verify_with_publisher` → `spawn_verified` → each of ~30 `spawn_<x>_capsule()` call sites that build `CapsuleSpecVerified`. The compiler will refuse to build until every spawn site passes a name — that pressure is intentional, it guarantees full coverage. The spawn site passes the same string it uses for `boot_log::*(prefix, ...)` so the names align.

### 3.3 blake3 self-test (defensive)

In `boot_baseline::init_boot_baseline()`, hash a known 1024-byte input filled with `0xAA` and compare against a pre-computed expected hash (constant string literal). If wrong → panic with a clear "blake3 implementation broken" message. Rules out H4 in one line.

### 3.4 Decision table (what each outcome means)

| Boot baseline hash vs manifest.payload_hash | Verify-time hash vs boot baseline | Verdict |
|---|---|---|
| equal | equal | **H5 (comparison bug).** Bytes are fine, hashes are fine, but `!=` returns true. Investigate `decode/header.rs:44` and the `[u8; 32]` comparison. |
| equal | **different** | **H1 / H2 / H3 (runtime corruption).** Track the writer. Most likely H3 (ELF loader bleed). Next step: instrument the ELF loader to dump the embedded byte range before/after. |
| **different** | n/a | **Setup/ceremony bug** — the embedded bytes never matched the manifest. Most likely an `include_bytes!` path drift or a stale build. Audit the per-capsule embed.rs paths vs the make-target output paths. |
| (blake3 self-test fails at boot) | n/a | **H4 (blake3 bug).** Replace the implementation or pin a different version. |

The diagnostic is designed so a **single boot** writes enough information to the serial log to classify the failure for every capsule that fails verification.

## 4. Fix design (per diagnostic outcome)

The fix is **outcome-driven** — we cannot finalize it before the diagnostic boot. But the shape of each branch is sketched here so the implementation plan can pre-stage skeleton commits:

### 4.1 If H1/H2/H3 (runtime corruption) — most likely

**Mitigation (always safe):** at the start of `verify_with_publisher`, copy `payload`, `nonos_id_cert_bytes`, `manifest_bytes` into freshly-allocated `Vec<u8>` buffers and verify against those. This removes the embedded slice from the verification path entirely; the verifier no longer trusts that its inputs are stable.

- Files: `src/security/capsule_manifest/verify/mod.rs` (~15 lines).
- Cost: 1 allocation + 1 memcpy per spawn × 3 buffers. Negligible (capsules spawn 34 times at boot, never after).
- This is a **defensive fix** that hides H1/H2/H3 if we don't also chase the root writer. We should:
  1. Land the defensive copy first (unblocks GUI).
  2. Add a permanent invariant check: `assert_eq!(blake3(slice_at_spawn), boot_baseline.elf, capsule_name)` so a future regression is caught immediately, not days later.
  3. Track down the writer (H3 most likely — ELF loader). Land a real fix that removes the need for the defensive copy.

### 4.2 If H4 (blake3 bug)

Pin `blake3` to a specific known-good version, or switch features (try without `pure`, or use a different no_std hash). Add a permanent boot-time self-test (already in §3.3) so a regression is caught instantly.

- Files: `Cargo.toml` + maybe a wrapper module if we swap implementations.

### 4.3 If H5 (comparison bug)

Audit `manifest.payload_hash` comparison. Likely fix: use `subtle::ConstantTimeEq` or `<[u8; 32]>::eq` explicitly. Or check if `&payload_hash[..] == &computed[..]` differs from `payload_hash == computed` (it shouldn't, but compiler bugs exist).

- Files: `src/security/capsule_manifest/verify/payload.rs` + `cert_binding.rs` (1-line change).

### 4.4 If setup/ceremony bug (different on first hash)

Audit per-capsule embed.rs paths vs Capsule.mk output paths. The capsules where boot baseline differs from manifest are the ones with the path drift. Fix is per-capsule.

## 5. Architecture & component boundaries

```
┌─────────────────────────────────────────┐
│  microkernel_init (kernel_core)         │
│    ↓ calls                              │
│  boot_baseline::init_boot_baseline()    │  ← new
│    ↓ iterates                           │
│  Per-capsule (name, ELF, CERT, MF)      │
│    ↓ writes                             │
│  static BOOT_BASELINE map               │  ← new
└─────────────────────────────────────────┘
                  ↓ (later, at spawn time)
┌─────────────────────────────────────────┐
│  spawn_<x>_capsule()                    │
│    ↓ passes capsule_name + spec to      │
│  spawn_verified                         │
│    ↓ forwards to                        │
│  verify_with_publisher                  │  ← modified: takes capsule_name
│    ↓ calls                              │
│  cert_binding::check + payload::check   │  ← modified: log + baseline-compare
└─────────────────────────────────────────┘
```

Each unit has one clear purpose:
- `boot_baseline` — owns the canonical hashes at the moment the kernel image starts running.
- `verify` — does the cryptographic check, now augmented with diagnostic logging that uses `boot_baseline` as a side input.
- `spawn` — thin shim passing the capsule name into the verify chain so logs are attributable.

## 6. Data flow

Boot → init → `init_boot_baseline()` populates the map → init returns → userland spawn loop begins → for each `spawn_X_capsule()` call, the verifier logs `(input_ptr, input_len, input_first_16, computed_hash, expected_hash, boot_baseline_hash)`. On mismatch, additionally logs the categorization verdict from §3.4.

## 7. Error handling

The instrumentation never changes verifier behavior:
- If `BOOT_BASELINE` is not yet initialized when verify is called, log `boot_baseline=uninit` and proceed (this is a bug we should never hit, but a panic in the verifier is worse than a log line).
- If a capsule name is not in the map, log `boot_baseline=unknown` and proceed.
- The blake3 self-test in §3.3 IS a hard panic, because every other diagnostic conclusion is meaningless if blake3 is broken.

The eventual fix (§4.1) DOES change behavior: it adds a defensive copy and an invariant assertion. The assertion fires on a regression. It is `debug_assert!`-style behind a feature flag if we don't want to ship the runtime cost; default-on in dev builds.

## 8. Testing

- **Host:** `cargo test --release --test artifacts` continues to pass (we haven't changed the on-disk chain).
- **Kernel build:** `make nonos-mk-desktop-gui-prod` must build clean. The new `capsule_name` parameter ripples through ~30 spawn sites; the build will catch any miss.
- **Boot:** one instrumented `make nonos-mk-run-serial` ≥ 240s captures the diagnostic output. The success criterion is **the log contains enough data to fill in §3.4 for every failing capsule** — we don't need GUI to render on this boot; we need data.
- **Post-fix boot:** the SAME boot run (same kernel binary) must produce a deterministic verify-pass for every capsule, repeated 3 times to defeat flakiness.

## 9. Implementation order

The implementation plan that follows this spec must respect this order:

1. Wire the `capsule_name: &str` parameter through `verify_with_publisher` → `cert_binding::check` → `payload::check` first (build will fail at all spawn sites until each is updated; that's the right pressure to catch every caller).
2. Land `boot_baseline.rs` with self-test (§3.3) gated by a separate commit so the self-test outcome is unambiguous in `git bisect`.
3. Add the verifier-side logging.
4. Build + boot + capture.
5. **Decide the fix from the data**, not before.
6. Land the targeted fix per §4.x.
7. Land the permanent defensive check (§4.1 step 2) as a separate commit so it can be feature-gated.

## 10. Scope cap

This spec is exactly what's needed to root-cause and fix the trust-verifier non-determinism. Out of scope per §0: the trust ceremony, MSI-X, capsule set membership, manifest schema. The implementation plan derived from this spec must not grow into those.
