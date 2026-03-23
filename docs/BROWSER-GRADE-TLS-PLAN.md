# Browser-Grade TLS — Implementation Plan

## Overview

Upgrade the NONOS kernel's TLS 1.3 implementation from minimal proof-of-concept to
browser-grade compatibility — covering certificate verification (Phases 1-5, COMPLETE)
and TLS handshake protocol support (Phases 6-9, IN PROGRESS).

**Phases 1-5 (Certificate Verification)** — COMPLETE, committed through `73a7b9a7`:
- Full X.509v3 extension parsing (BC, KU, EKU, SKI, AKI)
- 25 trusted root CAs with full Subject DN + SPKI + SKI
- Chain-to-root verification via DN matching + AKI→SKI + signature verification
- Policy enforcement (BC, KU, EKU, pathLen per RFC 5280)
- 1731 tests passing, google.com verified working

**Phases 6-9 (TLS Handshake Compatibility)** — IN PROGRESS:
- HelloRetryRequest + P-256 ECDH (Phase 6) — fixes facebook.com
- AES-256-GCM-SHA384 cipher suite (Phase 7) — fixes amazon.com
- Extended signature algorithms (Phase 8) — broadens server compatibility
- Dual key share optimization (Phase 9) — eliminates HRR latency

---

## Phase 1 — Extension Parser Infrastructure ✅

**Status:** COMPLETE — committed `c57fe677`

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

## Phase 2 — Trust Store Upgrade ✅

**Status:** COMPLETE — committed `6bd04103`

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

- [x] Define `TrustedRootCa` struct:
  - [x] `name: &'static str`
  - [x] `subject_der: &'static [u8]` (DER-encoded Subject DN)
  - [x] `spki_der: &'static [u8]` (full SPKI for signature verification)
  - [x] `spki_sha256: [u8; 32]` (backward compat / fast pre-filter)
  - [x] `ski: Option<&'static [u8]>` (Subject Key Identifier)
- [x] Build extraction tool (`tools/extract_root_cas.py`) that reads PEM root CAs → generates Rust source
- [x] Source root CAs from curated PEM bundle (42 roots + intermediates)
- [x] Regenerate all `store/*.rs` files with `TrustedRootCa` entries (subject_der, spki_der, spki_sha256, ski)
- [x] Keep `RootCaFingerprint` temporarily for backward compatibility
- [x] Add `find_roots_by_subject_dn()` function to `verify.rs`
- [x] Add `find_roots_by_ski()` function to `verify.rs`
- [x] Export new types and functions from `root_certs/mod.rs`
- [x] 12 unit tests (DN lookup, SKI lookup, SPKI hash integrity, data consistency)
- [x] `cargo test --features std` passes (1689 tests, 0 failures)
- [x] `cargo clippy` clean

---

## Phase 3 — Chain Building Upgrade ✅

**Status:** COMPLETE — committed `9c88cc19`, chain-to-root fix `73a7b9a7`

**Goal:** Match browser behavior — verify topmost cert's signature against root's
public key via issuer DN matching, instead of SPKI hash lookup.

### Files

| Action | File |
|--------|------|
| Modify | `src/network/onion/tls/root_certs/verify.rs` |
| Modify | `src/network/onion/tls/verify/https.rs` |
| Modify | `src/network/onion/nonos_crypto/x509_verify/chain.rs` |

### Checklist

- [x] Implement `verify_chain_to_root()`:
  - [x] Step 1: Find candidate roots where `topmost.issuer_der == root.subject_der`
  - [x] Step 2: If topmost has AKI, filter candidates by SKI
  - [x] Step 3: Verify topmost's signature with each candidate root's SPKI
  - [x] Return matching root on success
- [x] Add `verify_signature_with_spki(tbs, sig, sig_alg, spki_der)` helper
- [x] Replace `verify_trusted_root()` call in `https.rs` with `verify_chain_to_root()`
- [x] Handle cross-signed roots (multiple roots may share Subject DN)
- [x] Handle server sending root in chain (detect self-signed topmost)
- [x] Add chain depth limit (max 10 certs)
- [ ] Test with real chains: Let's Encrypt, Google GTS, Cloudflare, DigiCert
- [x] Verify old SPKI-hash path still works as fallback during migration
- [x] `cargo test --features std` passes (1704 tests, 0 failures)
- [ ] `cargo clippy` clean
- [ ] `make run-serial` boots without new errors

---

## Phase 4 — Policy Enforcement ✅

**Status:** COMPLETE — committed `303678df`

**Goal:** Enforce certificate policies (EKU, KU, pathLen, BC) like browsers do.

### Files

| Action | File |
|--------|------|
| Modify | `src/network/onion/nonos_crypto/x509_verify/constraints.rs` |
| Modify | `src/network/onion/nonos_crypto/x509_verify/chain.rs` |
| Modify | `src/network/onion/tls/verify/https.rs` |

### Checklist

- [x] **Basic Constraints enforcement** in chain walk:
  - [x] All non-leaf certs must have `is_ca == true`
  - [x] `pathLenConstraint` enforced (certs-below-CA ≤ pathLen)
- [x] **EKU enforcement** on leaf cert:
  - [x] If EKU present, must contain `ServerAuth` for HTTPS connections
  - [x] If EKU absent, allow (RFC 5280 §4.2.1.12)
- [x] **Key Usage enforcement**:
  - [x] CA certs must have `keyCertSign` bit
  - [x] Leaf certs should have `digitalSignature` bit
  - [x] If KU absent, allow (RFC 5280 §4.2.1.3)
- [x] **Chain depth hard limit**: reject chains > 10 certs
- [x] Tests: craft invalid chains (wrong EKU, missing BC, pathLen exceeded)
- [x] Tests: valid chains still pass
- [x] `cargo test --features std` passes (1724 tests, +20 from Phase 4)
- [ ] `cargo clippy` clean

---

## Phase 5 — Cleanup & Hardening ✅

**Status:** COMPLETE — committed `527253c3`

**Goal:** Remove intermediate SPKI workaround, harden edge cases.

### Files

| Action | File |
|--------|------|
| Delete | `src/network/onion/tls/root_certs/store/intermediates.rs` |
| Modify | `src/network/onion/tls/root_certs/store/mod.rs` |
| Modify | `src/network/onion/nonos_crypto/x509_san/san.rs` (optional refactor) |
| Modify | `src/network/onion/nonos_crypto/x509_verify/chain.rs` |

### Checklist

- [x] Delete `store/intermediates.rs`
- [x] Remove intermediate groups from `TRUSTED_ROOT_GROUPS`:
  - [x] `LETSENCRYPT_INTERMEDIATES`
  - [x] `DIGICERT_INTERMEDIATES`
  - [x] `SECTIGO_INTERMEDIATES`
  - [x] `MICROSOFT_INTERMEDIATES`
- [x] Remove `RootCaFingerprint` type (replaced by `TrustedRootCa`)
- [x] Remove `is_trusted_root()` SPKI-hash function (replaced by DN+sig verify)
- [x] Remove `verify_trusted_root()` legacy function
- [x] Remove SPKI-hash fallback from `verify_chain_to_root()`
- [x] Optional: migrate SAN parsing from raw byte scan to extension parser
- [x] Optional: DN normalization (case-insensitive PrintableString per RFC 5280 §7.1)
- [x] Optional: tighten time validity (warn instead of silent skip when clock < 2020)
- [ ] Verify TLS connections to top 20 sites still work under QEMU
- [x] `cargo test --features std` passes (1729 tests, +6 from optional items)
- [ ] `cargo clippy` clean
- [ ] `make run-serial` boots without new errors

---

## Phase 1-5 Dependency Graph

```
Phase 1 (Extensions) ──→ Phase 2 (Trust Store) ──→ Phase 3 (Chain Building)
         │                                                    │
         └──→ Phase 4 (Policy Enforcement) ←─────────────────┘
                          │
                          └──→ Phase 5 (Cleanup)
```

All 5 phases COMPLETE. Total: 1731 tests passing.

## Phase 1-5 Code Impact (Actual)

| Phase | New Lines | Modified Lines | Deleted Lines |
|-------|-----------|----------------|---------------|
| 1     | ~180      | ~40            | ~10           |
| 2     | ~200      | ~100           | ~50           |
| 3     | ~80       | ~60            | ~20           |
| 4     | ~60       | ~40            | ~5            |
| 5     | ~0        | ~20            | ~120          |

---

## Phase 6 — HelloRetryRequest + P-256 ECDH ✅

**Status:** COMPLETE
**Priority:** HIGHEST — fixes facebook.com (and any server that demands P-256 over X25519)
**Root cause:** Server sends HelloRetryRequest choosing P-256; our client doesn't detect
HRR, tries to derive X25519 shared secret from HRR response → parse error or wrong
derivation → handshake timeout.

### Background

TLS 1.3 HelloRetryRequest (RFC 8446 §4.1.4) is a ServerHello with the special `random`
value `CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91 C2 A2 11 16 7A BB 8C 5E 07 9E
09 E2 C8 A8 33 9C`. When a server's preferred group differs from the client's key_share,
it sends HRR with `selected_group` in the key_share extension (just 2 bytes — the group
ID, no public key). The client must then:

1. Replace the transcript hash with a synthetic `message_hash` construct
2. Generate a new key pair for the requested group
3. Send a new ClientHello (ClientHello2) with the correct key_share
4. Resume the normal handshake from the second ServerHello

### Files

| Action | File |
|--------|------|
| **New** | `src/crypto/asymmetric/p256/ecdh.rs` |
| Modify | `src/crypto/asymmetric/p256/mod.rs` |
| Modify | `src/network/onion/tls/crypto_provider/traits.rs` |
| Modify | `src/network/onion/tls/crypto_provider/kernel.rs` |
| Modify | `src/network/onion/tls/protocol/server_hello.rs` |
| Modify | `src/network/onion/tls/protocol/client_hello.rs` |
| Modify | `src/network/onion/tls/connection/types.rs` |
| Modify | `src/network/onion/tls/connection/poll_hello.rs` |
| Modify | `src/network/onion/tls/transcript.rs` |
| Modify | `src/network/onion/tls/types.rs` |

### Checklist

**Step 1 — P-256 ECDH primitive** ✅

- [x] Create `src/crypto/asymmetric/p256/ecdh.rs`:
  - [x] `p256_ecdh_keypair() -> (SecretKey, PublicKey)` — generate random scalar, compute uncompressed public point (0x04 || x || y)
  - [x] `p256_ecdh(sk: &[u8; 32], peer_pub: &[u8; 65]) -> Option<[u8; 32]>` — decompress peer point, scalar multiply, return x-coordinate
  - [x] Validate peer point is on curve (not identity, not low-order)
  - [x] Reuse existing `AffinePoint`, `ProjectivePoint`, `P256Scalar`, `P256FieldElement` from `p256/`
- [x] Add `pub mod ecdh;` to `src/crypto/asymmetric/p256/mod.rs`
- [x] Unit tests: NIST SP 800-56A test vector, round-trip, reject identity/invalid/zero scalar (6 tests)

**Step 2 — TlsCrypto trait extensions** ✅

- [x] Add to `TlsCrypto` trait in `traits.rs`:
  ```rust
  fn p256_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), OnionError>;  // (secret, pub65)
  fn p256_ecdh(&self, sk: &[u8], peer_pub: &[u8]) -> Result<[u8; 32], OnionError>;
  ```
- [x] Implement in `kernel.rs` — delegate to `crypto::asymmetric::p256::ecdh::*`

**Step 3 — ServerHello HRR detection** ✅

- [x] Add `HRR_RANDOM` constant to `server_hello.rs`:
  ```rust
  const HRR_RANDOM: [u8; 32] = [
      0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
      0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
      0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
      0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
  ];
  ```
- [x] Add `pub fn is_hello_retry_request(random: &[u8; 32]) -> bool`
- [x] Modify `parse_server_hello()` to handle HRR's key_share extension:
  - When HRR, key_share extension contains only `selected_group` (2 bytes), not a full key share
  - Return a `ServerHelloResult` enum: `Normal { suite, server_pub, random }` or `HelloRetryRequest { suite, selected_group, random }`

**Step 4 — ClientHello P-256 support** ✅

- [x] Add `0x0017` (secp256r1) to `supported_groups` extension in `client_hello.rs`
  - Offer both: `[0x001d, 0x0017]` (X25519 preferred, P-256 as fallback)
- [x] Create `build_client_hello_retry()` that accepts:
  - `group: u16` — the selected group for key_share
  - `epk: &[u8]` — variable-length public key (32 for X25519, 65 for P-256)
  - Cookie extension (if server sent one in HRR)

**Step 5 — Transcript rewrite for HRR** ✅

- [x] Add `replace_with_message_hash()` to `Transcript`:
  ```rust
  pub(super) fn replace_with_message_hash(&mut self) {
      // RFC 8446 §4.4.1: Hash(message_hash || 00 || hash_len || Hash(CH1))
      let hash = self.state;  // current hash = Hash(CH1)
      self.buffer.clear();
      // Synthetic handshake header: type=254, length=hash_len
      self.buffer.push(254); // message_hash type
      self.buffer.push(0);
      self.buffer.push(0);
      self.buffer.push(32); // SHA-256 hash length
      self.buffer.extend_from_slice(&hash);
      self.update();
  }
  ```

**Step 6 — Connection state machine** ✅

- [x] Add fields to `TLSConnection`: `hrr_count`, `server_group`, `sni_cache`, `alpn_cache`
- [x] Change `server_pub: [u8; 32]` → `Vec<u8>` for variable-size key shares
- [x] Rewrite `poll_server_hello()` to dispatch on `ServerHelloResult`:
  - HRR path: validate hrr_count, transcript rewrite, new keypair, build+send CH2
  - Normal path: ECDH dispatch by group (X25519 0x001d / P-256 0x0017)
- [x] Update `start_handshake()` to cache SNI/ALPN for HRR rebuilds

**Step 7 — CipherSuite plumbing** ✅

- [x] Existing 0x1301 / 0x1303 match in `handle_normal_sh()` — no changes needed
  - Phase 7 will add `0x1302`

### Tests

- [x] P-256 ECDH: round-trip, NIST vector, identity/invalid/zero rejection (6 tests)
- [x] `cargo test --features std` passes — 1737 tests, 0 failures
- [ ] `make run-serial` boots
- [ ] Verify facebook.com connects successfully in QEMU

---

## Phase 7 — AES-256-GCM-SHA384 Cipher Suite

**Status:** Not started
**Priority:** HIGH — fixes amazon.com and servers that prefer `TLS_AES_256_GCM_SHA384`
**Root cause:** Our ClientHello offers only 2 cipher suites (0x1301, 0x1303). Servers
preferring `TLS_AES_256_GCM_SHA384` (0x1302) may either downgrade to a less-preferred
suite or reject the handshake entirely. The key schedule, transcript, and AEAD are all
hardcoded to SHA-256 / 32-byte hashes.

### Background

`TLS_AES_256_GCM_SHA384` (0x1302) uses:
- SHA-384 for transcript hash (48-byte output)
- HMAC-SHA-384 for HKDF extract/expand
- AES-256-GCM for record encryption (32-byte key)

All three crypto primitives already exist in the kernel:
- `src/crypto/hash/sha384.rs` — SHA-384 hash
- `src/crypto/symmetric/aes_gcm/aes256.rs` — AES-256-GCM seal/open
- Missing: HMAC-SHA-384, HKDF-SHA-384 wrappers only

The main challenge is **hash agility**: refactoring `Transcript`, `KeySchedule`, `Secret`,
`AeadState`, and `TlsCrypto` to support variable hash output sizes (32 for SHA-256, 48
for SHA-384).

### Files

| Action | File |
|--------|------|
| **New** | `src/crypto/hash/hmac_sha384.rs` (or extend existing hmac) |
| Modify | `src/crypto/hash/mod.rs` |
| Modify | `src/network/onion/tls/types.rs` |
| Modify | `src/network/onion/tls/crypto_provider/traits.rs` |
| Modify | `src/network/onion/tls/crypto_provider/kernel.rs` |
| Modify | `src/network/onion/tls/transcript.rs` |
| Modify | `src/network/onion/tls/keys.rs` |
| Modify | `src/network/onion/tls/aead.rs` |
| Modify | `src/network/onion/tls/protocol/client_hello.rs` |
| Modify | `src/network/onion/tls/connection/poll_hello.rs` |
| Modify | `src/network/onion/tls/connection/types.rs` |

### Checklist

**Step 1 — HMAC-SHA-384 / HKDF-SHA-384 primitives**

- [ ] Create HMAC-SHA-384 function: `hmac_sha384(key, data) -> [u8; 48]`
  - Reuse SHA-384 (SHA-512 engine with different IV) with HMAC construction
- [ ] Create HKDF-SHA-384 extract: `hkdf_sha384_extract(salt, ikm) -> [u8; 48]`
- [ ] Create HKDF-SHA-384 expand: `hkdf_sha384_expand(prk, info, out)`
- [ ] Unit tests with RFC 5869 test vectors for SHA-384

**Step 2 — TlsCrypto trait: hash-agile methods**

- [ ] Add to `TlsCrypto` trait:
  ```rust
  fn sha384(&self, data: &[u8], out48: &mut [u8; 48]);
  fn hmac_sha384(&self, key: &[u8], data: &[u8], out48: &mut [u8; 48]);
  fn hkdf_extract_384(&self, salt: &[u8; 48], ikm: &[u8], out48: &mut [u8; 48]);
  fn hkdf_expand_384(&self, prk: &[u8; 48], info: &[u8], out: &mut [u8]);
  fn hash_len(&self, suite: CipherSuite) -> usize;  // 32 or 48
  ```
- [ ] Implement in `kernel.rs`

**Step 3 — CipherSuite variant**

- [ ] Add `TlsAes256GcmSha384 = 0x1302` to `CipherSuite` enum in `types.rs`
- [ ] Add `0x1302` to `build_client_hello()` cipher suite list (offer 3 suites)
- [ ] Update `poll_server_hello()` suite match to accept `0x1302`

**Step 4 — Hash-agile Transcript**

- [ ] Refactor `Transcript` to hold `state: Vec<u8>` (32 or 48 bytes) instead of `[u8; 32]`
  - Or use `state: [u8; 48]` with `hash_len: usize` field
- [ ] Parameterize `Transcript::new(suite: CipherSuite)` — select SHA-256 or SHA-384
- [ ] `update()` dispatches to `sha256()` or `sha384()` based on suite
- [ ] `hash()` returns `&[u8]` (dynamic length) instead of `&[u8; 32]`
- [ ] Update `replace_with_message_hash()` (from Phase 6) to use hash_len

**Step 5 — Hash-agile Key Schedule**

- [ ] Refactor `Secret` to hold `secret: Vec<u8>` (32 or 48 bytes)
- [ ] Refactor `KeySchedule` PRK fields to `Vec<u8>` (32 or 48 bytes)
  - Or use `[u8; 48]` with `hash_len: usize`, truncating for SHA-256
- [ ] `derive_after_sh()` and `derive_application()` dispatch to SHA-256 or SHA-384 HKDF
- [ ] `expand_label()` and `expand_label_len()` accept `&[u8]` PRK (not `&[u8; 32]`)
- [ ] All zeroization in `Drop` still covers the full buffer

**Step 6 — AEAD: AES-256-GCM arm**

- [ ] Add `CipherSuite::TlsAes256GcmSha384` arm to `AeadState::from_secret()`:
  - `key_len = 32`, use `aes256_gcm_encrypt` / `aes256_gcm_decrypt`
- [ ] Update `seal()` and `open()` dispatch to call AES-256-GCM for suite 0x1302
- [ ] Note: `expand_label_len` PRK is now 48 bytes for this suite

**Step 7 — Connection state: variable-size hashes**

- [ ] `cert_verify_hash: Vec<u8>` in `TLSConnection` (32 or 48 bytes)
  - Or `[u8; 48]` with `hash_len` field
- [ ] All places that pass `&[u8; 32]` to key schedule / transcript must handle 48-byte variant

### Tests

- [ ] HMAC-SHA-384: RFC 5869 vectors
- [ ] HKDF-SHA-384 extract/expand: known vectors
- [ ] Key schedule with SHA-384: derive test vectors
- [ ] AES-256-GCM AEAD round-trip through TLS record layer
- [ ] `cargo test --features std` passes
- [ ] `make run-serial` boots
- [ ] Verify amazon.com connects successfully in QEMU

---

## Phase 8 — Extended Signature Algorithms

**Status:** Not started
**Priority:** MEDIUM — quick win to support more servers
**Root cause:** Only 4 signature algorithms in ClientHello and `verify_certificate_signature()`.
Servers using RSA-PSS-SHA-384 or RSA-PKCS1-SHA-256 are rejected. Many CDNs and enterprise
servers use these algorithms.

### Background

Currently supported (in ClientHello `signature_algorithms` and CertificateVerify):
| Code | Algorithm |
|------|-----------|
| `0x0403` | ECDSA-P256-SHA256 |
| `0x0503` | ECDSA-P384-SHA384 |
| `0x0804` | RSA-PSS-SHA-256 |
| `0x0807` | Ed25519 |

Missing but commonly used:
| Code | Algorithm | Existing Crypto? |
|------|-----------|------------------|
| `0x0805` | RSA-PSS-SHA-384 | SHA-384 ✅, RSA-PSS needs SHA-384 variant |
| `0x0401` | RSA-PKCS1-SHA-256 | SHA-256 ✅, RSA needs PKCS#1 v1.5 verify |
| `0x0501` | RSA-PKCS1-SHA-384 | SHA-384 ✅, RSA needs PKCS#1 v1.5 verify |

### Files

| Action | File |
|--------|------|
| Modify | `src/network/onion/tls/protocol/client_hello.rs` |
| Modify | `src/network/onion/tls/connection/verify_cert.rs` |
| Modify | `src/network/onion/tls/crypto_provider/traits.rs` |
| Modify | `src/network/onion/tls/crypto_provider/kernel.rs` |
| Modify | `src/crypto/asymmetric/rsa/` (if PKCS#1 v1.5 verify doesn't exist) |

### Checklist

**Step 1 — New verify methods on TlsCrypto**

- [ ] Add to trait:
  ```rust
  fn verify_rsa_pss_sha384(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool;
  fn verify_rsa_pkcs1_sha256(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool;
  fn verify_rsa_pkcs1_sha384(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool;
  ```
- [ ] Implement in `kernel.rs`:
  - RSA-PSS-SHA-384: reuse RSA-PSS engine with SHA-384 hash
  - RSA-PKCS#1-SHA-256: implement PKCS#1 v1.5 signature verification
  - RSA-PKCS#1-SHA-384: same engine, different hash

**Step 2 — Expand ClientHello signature_algorithms**

- [ ] Update `sigs` array in `build_client_hello()`:
  ```rust
  let sigs: [u16; 7] = [0x0403, 0x0503, 0x0804, 0x0805, 0x0807, 0x0401, 0x0501];
  ```
- [ ] Update the length prefix to match: `14u16` (7 × 2 bytes)

**Step 3 — Expand CertificateVerify handler**

- [ ] Add arms to `verify_certificate_signature()` in `verify_cert.rs`:
  ```rust
  0x0805 => pk_kind == PublicKeyKind::Rsa && c.verify_rsa_pss_sha384(&pk_bytes, &to_be_signed, &self.cert_verify_sig),
  0x0401 => pk_kind == PublicKeyKind::Rsa && c.verify_rsa_pkcs1_sha256(&pk_bytes, &to_be_signed, &self.cert_verify_sig),
  0x0501 => pk_kind == PublicKeyKind::Rsa && c.verify_rsa_pkcs1_sha384(&pk_bytes, &to_be_signed, &self.cert_verify_sig),
  ```

### Tests

- [ ] RSA-PSS-SHA-384 verify: test vectors
- [ ] RSA-PKCS1-SHA-256 verify: test vectors
- [ ] RSA-PKCS1-SHA-384 verify: test vectors
- [ ] ClientHello contains all 7 sig algs
- [ ] CertificateVerify dispatches correctly for new algs
- [ ] `cargo test --features std` passes
- [ ] `make run-serial` boots

---

## Phase 9 — Dual Key Share (X25519 + P-256)

**Status:** Not started
**Priority:** LOW — optimization to avoid HRR round-trip latency
**Prerequisite:** Phase 6 (P-256 ECDH must work)

### Background

After Phase 6, servers that prefer P-256 will work via HelloRetryRequest, but HRR adds
one full round trip of latency. To eliminate this, we can send **both** X25519 and P-256
key shares in the initial ClientHello (Chrome, Firefox, and Safari all do this). The
server picks its preferred share and responds immediately — no HRR needed.

RFC 8446 §4.2.8 allows multiple `KeyShareEntry` items in `key_shares` extension:
```
key_share_entries: [
    { group: 0x001d, key_exchange: <X25519 pub 32 bytes> },
    { group: 0x0017, key_exchange: <P-256 pub 65 bytes> },
]
```

### Files

| Action | File |
|--------|------|
| Modify | `src/network/onion/tls/protocol/client_hello.rs` |
| Modify | `src/network/onion/tls/connection/poll_hello.rs` |
| Modify | `src/network/onion/tls/connection/types.rs` |
| Modify | `src/network/onion/tls/connection/handshake.rs` (or wherever `start_handshake` lives) |

### Checklist

- [ ] Modify `build_client_hello()` to accept multiple key shares:
  ```rust
  pub fn build_client_hello(
      cr: &[u8; 32],
      sni: Option<&str>,
      alpn: Option<&[&str]>,
      key_shares: &[(u16, &[u8])],  // [(group_id, public_key)]
  ) -> Vec<u8>
  ```
- [ ] In `start_handshake()`:
  - Generate X25519 keypair
  - Generate P-256 keypair
  - Store both ephemeral secrets
  - Pass `[(0x001d, &x25519_pub), (0x0017, &p256_pub)]` to `build_client_hello()`
- [ ] In `poll_server_hello()`:
  - Read `selected_group` from ServerHello key_share extension (already 2 bytes group + key)
  - If `0x001d`: use X25519 secret for ECDH
  - If `0x0017`: use P-256 secret for ECDH
- [ ] Update `TLSConnection` fields:
  - `x25519_secret: Option<[u8; 32]>`
  - `p256_secret: Option<Vec<u8>>`
  - Remove or repurpose `ephemeral_secret: Vec<u8>`

### Tests

- [ ] ClientHello contains both key shares (correct format)
- [ ] ServerHello X25519 selection → correct ECDH
- [ ] ServerHello P-256 selection → correct ECDH
- [ ] `cargo test --features std` passes
- [ ] `make run-serial` boots
- [ ] Verify facebook.com connects without HRR (single round trip)

---

## Updated Dependency Graph

```
Phase 1-5 (Certificate Verification — COMPLETE)
    │
    ├──→ Phase 6 (HRR + P-256 ECDH) ──→ Phase 9 (Dual Key Share)
    │         │
    │         └──→ Phase 7 (AES-256-GCM-SHA384)
    │
    └──→ Phase 8 (Extended Sig Algs)
```

**Recommended implementation order:** Phase 6 → Phase 8 → Phase 7 → Phase 9

- Phase 6 first: unblocks facebook.com and all P-256-preferring servers
- Phase 8 next: quick win, mostly wiring existing crypto, broadens compatibility
- Phase 7 after: most invasive (hash-agile refactor), fixes amazon.com
- Phase 9 last: pure optimization, reduces latency for P-256 servers

## Phase 6-9 Code Impact

| Phase | New Lines | Modified Lines | Deleted Lines | New Files |
|-------|-----------|----------------|---------------|-----------|
| 6     | ~200      | ~150           | ~10           | 1 (`p256/ecdh.rs`) |
| 7     | ~100      | ~250           | ~30           | 1 (`hmac_sha384.rs`) |
| 8     | ~50       | ~30            | ~0            | 0 |
| 9     | ~30       | ~60            | ~20           | 0 |

## Existing Crypto Inventory (Reusable)

| Primitive | Location | Status |
|-----------|----------|--------|
| P-256 field/scalar/point | `src/crypto/asymmetric/p256/` | ✅ Full impl |
| P-256 ECDSA sign/verify | `src/crypto/asymmetric/p256/` | ✅ Full impl |
| P-256 ECDH | `src/crypto/asymmetric/p256/ecdh.rs` | ❌ Missing — Phase 6 |
| AES-256-GCM | `src/crypto/symmetric/aes_gcm/aes256.rs` | ✅ Full impl |
| SHA-384 | `src/crypto/hash/sha384.rs` | ✅ Full impl |
| HMAC-SHA-256 | Exists | ✅ Full impl |
| HMAC-SHA-384 | — | ❌ Missing — Phase 7 |
| HKDF-SHA-256 | Exists | ✅ Full impl |
| HKDF-SHA-384 | — | ❌ Missing — Phase 7 |
| RSA-PSS-SHA-256 verify | Exists | ✅ Full impl |
| RSA-PSS-SHA-384 verify | — | ❌ Missing — Phase 8 |
| RSA-PKCS1-SHA-256 verify | — | ❌ Missing — Phase 8 |
| X25519 | Exists | ✅ Full impl |
| Ed25519 verify | Exists | ✅ Full impl |
| ChaCha20-Poly1305 | Exists | ✅ Full impl |

## Real-World Site Compatibility Matrix

| Site | Current | After Phase 6 | After Phase 7 | After Phase 8 | After Phase 9 |
|------|---------|---------------|---------------|---------------|---------------|
| google.com | ✅ | ✅ | ✅ | ✅ | ✅ |
| facebook.com | ❌ timeout | ✅ (via HRR) | ✅ | ✅ | ✅ (no HRR) |
| amazon.com | ❌ error | ❌ | ✅ | ✅ | ✅ |
| cloudflare.com | ✅ | ✅ | ✅ | ✅ | ✅ |
| github.com | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## Out of Scope

| Feature | Reason |
|---------|--------|
| AIA fetch | Circular dependency (HTTP during TLS handshake) |
| OCSP/CRL | Requires network I/O; defer to future work |
| Certificate Transparency | Requires CT log server access |
| CRLSets | Could embed at build time; consider post-Phase 5 |
| Name Constraints | Low real-world impact with root-only trust; stretch goal |
| TLS 1.2 fallback | Requires entirely separate handshake path; most modern servers support 1.3 |
| HTTP/2 (h2) | Application layer, not TLS — separate feature |
| 0-RTT (early data) | Security implications (replay attacks); not needed for browsing |
| Post-handshake auth | Rare in practice; not needed for HTTPS browsing |
