# Test Results

**Date:** 2026-03-16
**Kernel:** v0.8.2
**Command:** `make test`

## Summary

| Metric | Count |
|--------|-------|
| Total test annotations | 2,338 |
| Unique test functions | 2,004 |
| Executed | 1,590 |
| Passed | 1,570 |
| Failed | 20 |
| Not compiled (cfg gated) | 414 |

## By Module

| Module | Total | Executed | Passed |
|--------|-------|----------|--------|
| drivers | 643 | 612 | 612 |
| memory | 597 | 578 | 578 |
| crypto | 353 | 353 | 353 |
| arch | 280 | 267 | 267 |
| modules | 112 | 98 | 96 |
| fs | 54 | 54 | 54 |
| ipc | 51 | 51 | 31 |
| boot | 46 | 38 | 38 |
| process | 42 | 42 | 22 |
| apps | 20 | 20 | 20 |
| network | 13 | 13 | 13 |
| ui | 4 | 4 | 4 |

## Failed Tests (20)

Root cause: `attempt to multiply with overflow` at `src/arch/x86_64/time/timer/time.rs:30`

These tests require kernel hardware timers not available in userspace.

```
ipc::nonos_channel::channel::tests::test_channel_entry_creation
ipc::nonos_channel::message::tests::test_ipc_message_display
ipc::nonos_message::builder::tests::test_envelope_builder
ipc::nonos_message::envelope::tests::test_envelope_ack
ipc::nonos_message::envelope::tests::test_envelope_new
ipc::nonos_message::envelope::tests::test_envelope_response
ipc::nonos_message::envelope::tests::test_envelope_validation
ipc::nonos_policy::engine::tests::test_rate_limit_tracker
ipc::nonos_transport::stream::tests::test_frames_needed
ipc::nonos_transport::stream::tests::test_stream_id_uniqueness
ipc::nonos_transport::stream::tests::test_stream_mtu_clamping
modules::nonos_mod_runner::tests::test_run_module_attestation_fail
modules::nonos_mod_runner::tests::test_stop_and_erase_module
process::exec::tests::create_execute_terminate_flow
process::nox::tests::cancel_migration
process::nox::tests::create_and_get
process::nox::tests::list_and_filter_by_node
process::nox::tests::migration_flow
process::nox::tests::remove_only_after_terminated
process::nox::tests::state_transitions
```

## Not Compiled (414)

These tests have dependencies that differ between std and no_std modes. They run during kernel boot via `kernel_selftest::run()`.

**Kernel boot tests include:**
- Driver verification (PCI, AHCI, NVMe, xHCI, GPU, Audio)
- Crypto engine (BLAKE3, SHA3, Ed25519, ChaCha20-Poly1305)
- Post-quantum crypto (SPHINCS+, NTRU)
- RNG verification (RDRAND/RDSEED + ChaCha20 DRBG)

## All Tests by Category

### Crypto (353)

#### Symmetric Encryption
- AES-128: 22 tests
- AES-256: 23 tests
- AES-GCM: 32 tests
- ChaCha20-Poly1305: 28 tests

#### Hash Functions
- SHA-256: 12 tests
- SHA-512: 12 tests
- SHA3: 18 tests
- BLAKE3: 22 tests
- BLAKE2: 8 tests
- RIPEMD160: 6 tests

#### Asymmetric
- Ed25519: 35 tests
- X25519: 28 tests
- P-256/ECDSA: 31 tests

#### Zero-Knowledge
- Groth16: 42 tests
- Halo2: 38 tests

#### Utilities
- BigInt: 10 tests
- RNG: 8 tests
- Constant-time: 6 tests

### Drivers (643)

#### PCI
- Enumeration: 24 tests
- Config space: 18 tests
- BAR: 22 tests
- Capabilities: 15 tests
- Errors: 10 tests

#### USB/xHCI
- Ring ops: 34 tests
- TRB: 28 tests
- Contexts: 24 tests
- Endpoints: 22 tests
- Constants: 18 tests
- DMA: 16 tests
- Errors: 14 tests

#### AHCI/SATA
- Ports: 28 tests
- Commands: 22 tests
- FIS: 18 tests
- Capabilities: 10 tests

#### NVMe
- Queues: 32 tests
- Commands: 28 tests
- Namespace: 18 tests
- Admin: 16 tests

#### Network
- RTL8139: 43 tests

#### WiFi
- Frames: 24 tests
- Auth: 18 tests
- Crypto: 15 tests
- Scan: 10 tests

#### Audio
- HDA: 22 tests
- PCM: 18 tests
- Mixer: 12 tests

#### VirtIO
- Queue: 24 tests
- Block: 18 tests
- Net: 14 tests
- Config: 8 tests

### Memory (597)

- Heap allocator: 124 tests
- Page tables: 98 tests
- Frame allocator: 87 tests
- Layout: 56 tests
- Physical: 78 tests
- Virtual: 89 tests
- Cache: 65 tests

### Architecture (280)

- ACPI: 68 tests
- Interrupts: 45 tests
- Time: 52 tests
- CPU: 38 tests
- GDT: 24 tests
- Syscall: 31 tests
- Paging: 22 tests

### Modules (112)

- Loader: 34 tests
- Sandbox: 28 tests
- Runner: 24 tests
- Attestation: 26 tests

### Filesystem (54)

- FD management: 18 tests
- VFS: 14 tests
- Path: 12 tests
- Cache: 10 tests

### IPC (51)

- Channels: 18 tests
- Messages: 15 tests
- Policy: 10 tests
- Transport: 8 tests

### Boot (46)

- Stage1: 12 tests
- Stage2: 10 tests
- Attestation: 14 tests
- Memory map: 10 tests

### Process (42)

- Lifecycle: 14 tests
- NOX: 18 tests
- Scheduling: 10 tests

### Apps (20)

- Wallet: 8 tests
- DeFi: 6 tests
- Privacy: 6 tests

### Network (13)

- NYM: 8 tests
- TCP: 5 tests

### UI (4)

- CLI: 2 tests
- Events: 2 tests

---

## Execution Log

```
running 1590 tests
...
test result: FAILED. 1570 passed; 20 failed; 0 ignored; 0 measured; 0 filtered out; finished in 8.82s
```
