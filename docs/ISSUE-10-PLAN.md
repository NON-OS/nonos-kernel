# Issue #10 — Hardware Entropy & Network Support

**Branch:** `fix/issue-10-hw-entropy-network`  
**Date:** 2026-03-07  
**Severity:** Critical (security)  
**Status:** 🔴 In Progress

---

## Root Cause Analysis

| # | Severity | File | Bug |
|---|----------|------|-----|
| 1 | **CRITICAL** | `src/network/stack/core.rs:62` | smoltcp `random_seed = 0xD1E5_7A2C` — hardcoded across all boots → predictable TCP ISNs → session hijacking |
| 2 | **CRITICAL** | `src/drivers/virtio_rng/queue.rs` | VirtQueue desc/avail/used allocated as 3 separate DMA regions; legacy VirtIO programs single PFN expecting contiguous layout → device reads garbage → driver non-functional |
| 3 | **HIGH** | `src/drivers/init.rs` | `init_all_drivers()` never calls `init_virtio_rng()` → `kernel_main()` boot path has zero hardware entropy |
| 4 | **MEDIUM** | `src/crypto/util/rng/entropy/collect.rs` | Emergency entropy fallback (TSC jitter) used silently — no serial warning logged |
| 5 | **MEDIUM** | `Makefile:213-222` | `run-serial` and `debug` targets lack `-device e1000` — network untestable in CI/debug |

---

## Implementation Plan

### Phase 1 — P0 Security Fixes

- [ ] **1.1** Fix hardcoded smoltcp `random_seed` in `src/network/stack/core.rs:62`
  - Replace `0xD1E5_7A2C` with `crate::crypto::util::rng::random_u64()`
  - Add TSC-mixed fallback if RNG not yet initialized
  - Add debug log: `[NET] smoltcp seeded with hardware entropy`

- [ ] **1.2** Fix VirtQueue contiguous memory layout in `src/drivers/virtio_rng/queue.rs`
  - Allocate single contiguous DMA region for desc + avail + used
  - Layout per VirtIO 1.0 §2.6.2:
    - Desc table: offset 0, size = `QUEUE_SIZE * 16`
    - Avail ring: next 2-byte aligned, size = `6 + 2 * QUEUE_SIZE`
    - Used ring: next 4096-byte aligned, size = `6 + 8 * QUEUE_SIZE`
  - Compute pointers as offsets into single region
  - Add debug log: `[VIRTIO-RNG] Queue layout: desc=0x{:x} avail=0x{:x} used=0x{:x}`

- [ ] **1.3** Add `init_virtio_rng()` to `init_all_drivers()` in `src/drivers/init.rs`
  - Call after DMA pool init, before TPM/network probing
  - Log: `[VIRTIO-RNG] Hardware entropy source initialized` or `[VIRTIO-RNG] Not found (software RNG only)`

- [ ] **1.4** Phase 1 verification
  - `cargo build --release --target x86_64-nonos.json -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem`
  - Boot `make run-serial` — confirm:
    - `[VIRTIO-RNG] Hardware entropy source initialized`
    - `[NET] smoltcp seeded with hardware entropy`
    - No panics or OOM

### Phase 2 — Driver Quality & Hardening

- [ ] **2.1** Create `src/drivers/virtio_rng/error.rs`
  - `VirtioRngError` enum with variants: `NoPciManager`, `NoBarFound`, `UnsupportedBarType`, `QueueNotAvailable`, `DmaAllocationFailed`, `Timeout`, `NoDeviceFound`, `BufferEmpty`
  - Implement `as_str()`, `code()` (range `0x6xxx`), `is_recoverable()`, `Display`
  - Derive: `Debug, Clone, Copy, PartialEq, Eq`

- [ ] **2.2** Create `src/drivers/virtio_rng/types.rs`
  - Move `VirtqDesc`, `VirtqAvail`, `VirtqUsed`, `VirtqUsedElem` structs
  - Move VirtIO constants (`VIRTIO_STATUS_*`, `LEG_*`, `QUEUE_SIZE`, etc.)
  - All HW structs `#[repr(C)]`

- [ ] **2.3** Replace `&'static str` errors with `VirtioRngError`
  - Update `device.rs`, `queue.rs`, `init.rs`, `api.rs`
  - Update `mod.rs` re-exports

- [ ] **2.4** Add `// SAFETY:` comments to all ~12 unsafe blocks in `device.rs`
  - Port I/O: "port derived from PCI BAR0, validated during new()"
  - MMIO: "address derived from PCI BAR0 memory region"
  - DMA: "region allocated by alloc_dma_coherent with proper alignment"

- [ ] **2.5** Log emergency entropy fallback in `src/crypto/util/rng/entropy/collect.rs`
  - Add serial warning when falling through to `emergency_entropy_mix()`
  - `[RNG] WARNING: Using emergency entropy (TSC jitter) — no hardware RNG available`

- [ ] **2.6** Phase 2 verification
  - `cargo clippy` clean
  - `cargo build` succeeds
  - Boot `make run-serial` — no new warnings/errors

### Phase 3 — Makefile & Dev Parity

- [ ] **3.1** Add network device to `run-serial` Makefile target
  - Add `-device e1000,netdev=net0 -netdev user,id=net0`

- [ ] **3.2** Add network device to `debug` Makefile target
  - Add `-device e1000,netdev=net0 -netdev user,id=net0`

- [ ] **3.3** Phase 3 verification
  - `make run-serial` — confirm `[E1000]` init messages in serial output
  - `make debug` — confirm GDB attaches and network device visible

### Phase 4 — Tests & Final Validation

- [ ] **4.1** Add VirtQueue layout unit test in `queue.rs`
  - `test_virtqueue_layout_contiguous` — verify desc/avail/used are within single region at correct offsets

- [ ] **4.2** Add smoltcp seed test in `core.rs`
  - `test_random_seed_not_hardcoded` — verify seed is not the old `0xD1E5_7A2C` value

- [ ] **4.3** Full end-to-end verification
  - `cargo test --features std` — all tests pass
  - `make kernel` — builds clean
  - `make run-serial` — boot log shows:
    ```
    [VIRTIO-RNG] Hardware entropy source initialized
    [NET] smoltcp seeded with hardware entropy
    [E1000] Initialized successfully!
    [NONOS] Entering main loop
    ```
  - Wallet generates different addresses on successive boots

---

## Progress Log

| Date | Phase | Status | Notes |
|------|-------|--------|-------|
| 2026-03-07 | Investigation | ✅ Done | Found 5 bugs, 2 critical |
| 2026-03-07 | Scrum posted | ✅ Done | Comment on issue #10 |
| 2026-03-07 | Phase 1 | 🔴 Not started | |
| 2026-03-07 | Phase 2 | 🔴 Not started | |
| 2026-03-07 | Phase 3 | 🔴 Not started | |
| 2026-03-07 | Phase 4 | 🔴 Not started | |
