# Browser-Grade TLS Certificate Verification — Implementation Plan

## Overview

Upgrade the NONOS kernel's X.509 certificate verification pipeline from SPKI-hash-based
trust anchors to browser-grade chain-building with full root CA public keys, matching how
Chrome and Firefox validate TLS certificates.

**Current state:** 44 SPKI SHA-256 fingerprints (32 roots + 12 intermediates), no X.509
extension parsing, `is_ca` hardcoded `false`.

**Target state:** ~130 root CA certificates with full public keys, issuer DN → root
subject DN matching + signature verification, extension-based policy enforcement.

---

## Phase 1 — Extension Parser Infrastructure

**Goal:** Replace `skip_extensions()` with a real parser that extracts the 5 critical
X.509v3 extensions into a new struct on `X509Certificate`.

### Files

| Action | File |
|--------|------|
| **New** | `src/network/onion/nonos_crypto/x509_core/extensions.rs` |
| Modify | `src/network/onion/nonos_crypto/types.rs` |
| Modify | `src/network/onion/nonos_crypto/x509_core/tbs.rs` |
| Modify | `src/network/onion/nonos_crypto/x509_core/parse.rs` |
| Modify | `src/network/onion/nonos_crypto/x509_core/mod.rs` (if exists) |
| Modify | `src/network/onion/nonos_crypto/x509_verify/constraints.rs` |

### Checklist

- [x] Define `X509Extensions` struct in `types.rs`
  - [x] `basic_constraints: BasicConstraints` (is_ca + path_len)
  - [x] `key_usage: u16` (KU bit flags)
  - [x] `ext_key_usage: Vec<ExtKeyUsage>` (serverAuth, etc.)
  - [x] `subject_key_id: Option<Vec<u8>>`
  - [x] `authority_key_id: Option<Vec<u8>>`
- [x] Define `BasicConstraints` struct (ca: bool, path_len_constraint: Option<u8>)
- [x] Define `ExtKeyUsage` enum (ServerAuth, ClientAuth, OcspSigning)
- [x] Define KU bit constants (`KU_DIGITAL_SIGNATURE`, `KU_KEY_CERT_SIGN`, etc.)
- [x] Create `extensions.rs` with:
  - [x] `parse_extensions(parser, tbs_end) -> Result<X509Extensions, OnionError>`
  - [x] Extension OID dispatch (by raw DER OID bytes)
  - [x] `parse_basic_constraints(value)`
  - [x] `parse_key_usage(value)`
  - [x] `parse_ext_key_usage(value)`
  - [x] `parse_octet_string_value(value)` (for SKI)
  - [x] `parse_authority_key_id(value)` (for AKI)
  - [x] Unknown extensions → silently skip
- [x] Remove `skip_extensions()` from `tbs.rs`
- [x] Update `parse_tbs_fields()` return type (removed bool, extensions parsed separately)
- [x] Add `extensions: X509Extensions` field to `X509Certificate` in `types.rs`
- [x] Remove standalone `is_ca: bool` field (replaced by `extensions.basic_constraints.ca`)
- [x] Update `parse.rs` to call `parse_extensions()` and thread into `X509Certificate`
- [x] Update `constraints.rs` to read from `extensions.basic_constraints.ca`
- [x] Update all references to `cert.is_ca` throughout the codebase
- [ ] Unit tests: parse known extension DER blobs → assert correct values
- [x] `cargo test --features std` passes (1650 tests, 0 failures)
- [ ] `cargo clippy` clean

---

## Phase 2 — Trust Store Upgrade

**Goal:** Store full root CA certificates (Subject DN + SPKI + SKI) instead of only
SPKI SHA-256 hashes.

### Files

| Action | File |
|--------|------|
| Modify | `src/network/onion/tls/root_certs/types.rs` |
| New | `tools/extract_root_cas.rs` (build-time extraction tool) |
| Modify | `src/network/onion/tls/root_certs/store/*.rs` (all store files) |
| Modify | `src/network/onion/tls/root_certs/verify.rs` |

### Checklist

- [ ] Define `TrustedRootCa` struct:
  - [ ] `name: &'static str`
  - [ ] `subject_der: &'static [u8]` (DER-encoded Subject DN)
  - [ ] `spki_der: &'static [u8]` (full SPKI for signature verification)
  - [ ] `spki_sha256: [u8; 32]` (backward compat / fast pre-filter)
  - [ ] `ski: Option<&'static [u8]>` (Subject Key Identifier)
- [ ] Build extraction tool that reads PEM/DER root CAs → generates Rust source
- [ ] Source root CAs from Mozilla `certdata.txt` (or curated subset)
- [ ] Regenerate all `store/*.rs` files with `TrustedRootCa` entries
- [ ] Keep `RootCaFingerprint` temporarily for backward compatibility
- [ ] Add `find_roots_by_subject_dn()` function to `verify.rs`
- [ ] Add `find_roots_by_ski()` function to `verify.rs`
- [ ] Estimate `.rodata` size impact (~85 KB for ~130 roots)
- [ ] `cargo test --features std` passes
- [ ] `cargo clippy` clean

---

## Phase 3 — Chain Building Upgrade

**Goal:** Match browser behavior — verify topmost cert's signature against root's
public key via issuer DN matching, instead of SPKI hash lookup.

### Files

| Action | File |
|--------|------|
| Modify | `src/network/onion/tls/root_certs/verify.rs` |
| Modify | `src/network/onion/tls/verify/https.rs` |
| Modify | `src/network/onion/nonos_crypto/x509_verify/chain.rs` |

### Checklist

- [ ] Implement `verify_chain_to_root()`:
  - [ ] Step 1: Find candidate roots where `topmost.issuer_der == root.subject_der`
  - [ ] Step 2: If topmost has AKI, filter candidates by SKI
  - [ ] Step 3: Verify topmost's signature with each candidate root's SPKI
  - [ ] Return matching root on success
- [ ] Add `verify_signature_with_spki(tbs, sig, sig_alg, spki_der)` helper
- [ ] Replace `verify_trusted_root()` call in `https.rs` with `verify_chain_to_root()`
- [ ] Handle cross-signed roots (multiple roots may share Subject DN)
- [ ] Handle server sending root in chain (detect self-signed topmost)
- [ ] Add chain depth limit (max 10 certs)
- [ ] Test with real chains: Let's Encrypt, Google GTS, Cloudflare, DigiCert
- [ ] Verify old SPKI-hash path still works as fallback during migration
- [ ] `cargo test --features std` passes
- [ ] `cargo clippy` clean
- [ ] `make run-serial` boots without new errors

---

## Phase 4 — Policy Enforcement

**Goal:** Enforce certificate policies (EKU, KU, pathLen, BC) like browsers do.

### Files

| Action | File |
|--------|------|
| Modify | `src/network/onion/nonos_crypto/x509_verify/constraints.rs` |
| Modify | `src/network/onion/nonos_crypto/x509_verify/chain.rs` |
| Modify | `src/network/onion/tls/verify/https.rs` |

### Checklist

- [ ] **Basic Constraints enforcement** in chain walk:
  - [ ] All non-leaf certs must have `is_ca == true`
  - [ ] `pathLenConstraint` enforced (certs-below-CA ≤ pathLen)
- [ ] **EKU enforcement** on leaf cert:
  - [ ] If EKU present, must contain `ServerAuth` for HTTPS connections
  - [ ] If EKU absent, allow (RFC 5280 §4.2.1.12)
- [ ] **Key Usage enforcement**:
  - [ ] CA certs must have `keyCertSign` bit
  - [ ] Leaf certs should have `digitalSignature` bit
  - [ ] If KU absent, allow (RFC 5280 §4.2.1.3)
- [ ] **Chain depth hard limit**: reject chains > 10 certs
- [ ] Tests: craft invalid chains (wrong EKU, missing BC, pathLen exceeded)
- [ ] Tests: valid chains still pass
- [ ] `cargo test --features std` passes
- [ ] `cargo clippy` clean

---

## Phase 5 — Cleanup & Hardening

**Goal:** Remove intermediate SPKI workaround, harden edge cases.

### Files

| Action | File |
|--------|------|
| Delete | `src/network/onion/tls/root_certs/store/intermediates.rs` |
| Modify | `src/network/onion/tls/root_certs/store/mod.rs` |
| Modify | `src/network/onion/nonos_crypto/x509_san/san.rs` (optional refactor) |
| Modify | `src/network/onion/nonos_crypto/x509_verify/chain.rs` |

### Checklist

- [ ] Delete `store/intermediates.rs`
- [ ] Remove intermediate groups from `TRUSTED_ROOT_GROUPS`:
  - [ ] `LETSENCRYPT_INTERMEDIATES`
  - [ ] `DIGICERT_INTERMEDIATES`
  - [ ] `SECTIGO_INTERMEDIATES`
  - [ ] `MICROSOFT_INTERMEDIATES`
- [ ] Remove `RootCaFingerprint` type (replaced by `TrustedRootCa`)
- [ ] Remove `is_trusted_root()` SPKI-hash function (replaced by DN+sig verify)
- [ ] Optional: migrate SAN parsing from raw byte scan to extension parser
- [ ] Optional: DN normalization (case-insensitive PrintableString per RFC 5280 §7.1)
- [ ] Optional: tighten time validity (warn instead of silent skip when clock < 2020)
- [ ] Verify TLS connections to top 20 sites still work under QEMU
- [ ] `cargo test --features std` passes
- [ ] `cargo clippy` clean
- [ ] `make run-serial` boots without new errors

---

## Dependency Graph

```
Phase 1 (Extensions) ──→ Phase 2 (Trust Store) ──→ Phase 3 (Chain Building)
         │                                                    │
         └──→ Phase 4 (Policy Enforcement) ←─────────────────┘
                          │
                          └──→ Phase 5 (Cleanup)
```

## Estimated Code Impact

| Phase | New Lines | Modified Lines | Deleted Lines |
|-------|-----------|----------------|---------------|
| 1     | ~180      | ~40            | ~10           |
| 2     | ~200      | ~100           | ~50           |
| 3     | ~80       | ~60            | ~20           |
| 4     | ~60       | ~40            | ~5            |
| 5     | ~0        | ~20            | ~120          |

## Out of Scope

| Feature | Reason |
|---------|--------|
| AIA fetch | Circular dependency (HTTP during TLS handshake) |
| OCSP/CRL | Requires network I/O; defer to future work |
| Certificate Transparency | Requires CT log server access |
| CRLSets | Could embed at build time; consider post-Phase 5 |
| Name Constraints | Low real-world impact with root-only trust; stretch goal |
