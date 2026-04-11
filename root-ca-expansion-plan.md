# Root CA Trust Store Expansion — 26 → ~145 CAs

**Goal:** Production HTTPS coverage (99.9%+ of sites)
**Source of truth:** Mozilla NSS (via curl CA extract)
**Architecture:** One CA per file, directories per operator, mod.rs is exports only

---

## Code Standards

| Rule | Detail |
|------|--------|
| Max 75 lines per file | Hard cap. One CA per file for RSA, two ECC CAs if they fit. |
| No comments | Zero. File names and struct field names are self-documenting. |
| No license headers | License is in LICENSE file. |
| mod.rs is exports only | `pub mod`, `pub use`, and the group slice assembly. No logic. |

---

## Current Problem

Every existing store file violates the 75-line rule:

| File | Lines | CAs | Action |
|------|-------|-----|--------|
| `amazon.rs` | 197 | 4 | Split into 4 files |
| `digicert.rs` | 210 | 4 | Split into 4 files |
| `entrust.rs` | 382 | 8 | Split into 8 files |
| `globalsign.rs` | 153 | 3 | Split into 3 files |
| `google.rs` | 228 | 4 | Split into 4 files |
| `isrg.rs` | 124 | 2 | Split into 2 files |
| `others.rs` | 211 | 3 | Split into 3 files |
| `mod.rs` | 42 | — | Rewrite as exports only |

Total: 26 CAs across 7 oversized files → 26 CAs across 26 files in 8 directories.

Then add ~120 new CAs as ~120 new files across ~13 new operator directories.

---

## Target Directory Structure

```
src/network/onion/tls/root_certs/
  types.rs                              — TrustedRootCa struct (keep, 31 lines)
  verify/
    mod.rs                              — exports (keep, 21 lines)
    chain.rs                            — chain verification (keep, 63 lines)
    lookup.rs                           — root lookup (keep, 48 lines)
  store/
    mod.rs                              — TRUSTED_ROOT_GROUPS assembly (~60 lines)
    isrg/
      mod.rs                            — ISRG_ROOTS slice
      x1.rs                             — ISRG Root X1
      x2.rs                             — ISRG Root X2
    digicert/
      mod.rs                            — DIGICERT_ROOTS slice
      global.rs                         — DigiCert Global Root CA
      global_g2.rs                      — DigiCert Global Root G2
      global_g3.rs                      — DigiCert Global Root G3
      high_assurance_ev.rs              — DigiCert High Assurance EV Root CA
    amazon/
      mod.rs                            — AMAZON_ROOTS slice
      root_1.rs                         — Amazon Root CA 1
      root_2.rs                         — Amazon Root CA 2
      root_3.rs                         — Amazon Root CA 3
      root_4.rs                         — Amazon Root CA 4
    google/
      mod.rs                            — GOOGLE_ROOTS slice
      gts_r1.rs                         — GTS Root R1
      gts_r2.rs                         — GTS Root R2
      gts_r3.rs                         — GTS Root R3
      gts_r4.rs                         — GTS Root R4
    globalsign/
      mod.rs                            — GLOBALSIGN_ROOTS slice
      r1.rs                             — GlobalSign Root CA R1
      r3.rs                             — GlobalSign Root CA R3
      ecc_r5.rs                         — GlobalSign ECC Root CA R5
    entrust/
      mod.rs                            — ENTRUST_ROOTS slice
      starfield_g2.rs                   — Starfield Root CA G2
      godaddy_g2.rs                     — Go Daddy Root CA G2
      entrust_g2.rs                     — Entrust Root CA G2
      entrust_ec1.rs                    — Entrust Root CA EC1
      entrust_g4.rs                     — Entrust Root CA G4 (NEW)
      quovadis_2.rs                     — QuoVadis Root CA 2
      actalis.rs                        — Actalis Auth Root CA
      godaddy_class2.rs                 — GoDaddy Class 2 CA (NEW)
    microsoft/
      mod.rs                            — MICROSOFT_ROOTS slice
      rsa_2017.rs                       — Microsoft RSA Root CA 2017
      ecc_2017.rs                       — Microsoft ECC Root CA 2017
    comodo/
      mod.rs                            — COMODO_ROOTS slice
      rsa.rs                            — COMODO RSA CA
      usertrust_rsa.rs                  — USERTrust RSA CA
      usertrust_ecc.rs                  — USERTrust ECC CA
    sectigo/                            — NEW
      mod.rs
      public_server_r46.rs
      public_server_e46.rs
    identrust/                          — NEW
      mod.rs
      commercial_1.rs
      dst_x3.rs
    ssl_com/                            — NEW
      mod.rs
      root_rsa.rs
      root_ecc.rs
      ev_rsa.rs
    buypass/                            — NEW
      mod.rs
      class2.rs
      class3.rs
    certum/                             — NEW
      mod.rs
      trusted_network.rs
      trusted_network_2.rs
      ec384.rs
    affirmtrust/                        — NEW
      mod.rs
      commercial.rs
      networking.rs
      premium.rs
      premium_ecc.rs
    telia/                              — NEW
      mod.rs
      root_v2.rs
    swisssign/                          — NEW
      mod.rs
      gold_g2.rs
      silver_g2.rs
    trustwave/                          — NEW
      mod.rs
      global_g2.rs
      global_ecc.rs
    oiste/                              — NEW
      mod.rs
      gc.rs
      gb.rs
    government_eu/                      — NEW
      mod.rs
      dtrust_class3_2009.rs
      dtrust_ev_2009.rs
      dtrust_br_2020.rs
      dtrust_ev_2020.rs
      telekom_root_2.rs
      fnmt.rs
      fnmt_servidores.rs
      certigna.rs
      harica_rsa.rs
      harica_ecc.rs
      staat_nl_g3.rs
      atrust_05.rs
      etugra_rsa_v3.rs
      etugra_ecc_v3.rs
      izenpe.rs
    government_apac/                    — NEW
      mod.rs
      secom.rs
      twca_root.rs
      twca_global.rs
      cfca_ev.rs
      emsign_g1.rs
      emsign_c1.rs
      emsign_ecc_g3.rs
      emsign_ecc_c3.rs
      kisa_4.rs
      hkpost_3.rs
      security_comm_3.rs
      naver.rs
    regional/                           — NEW
      mod.rs
      certainly_r1.rs
      anf.rs
      microsec.rs
      tuntrust.rs
      disig.rs
      commscope_rsa.rs
      commscope_ecc.rs
```

---

## Phase 1: Refactor Existing Store

Split 7 oversized files into one-CA-per-file directories. No new CAs.

### Delete (replaced by directories)

- [x] `store/amazon.rs`
- [x] `store/digicert.rs`
- [x] `store/entrust.rs`
- [x] `store/globalsign.rs`
- [x] `store/google.rs`
- [x] `store/isrg.rs`
- [x] `store/others.rs`

### Create directories

- [x] `store/isrg/`
- [x] `store/digicert/`
- [x] `store/amazon/`
- [x] `store/google/`
- [x] `store/globalsign/`
- [x] `store/entrust/`
- [x] `store/microsoft/`
- [x] `store/comodo/`

### Create files — `store/isrg/`

- [x] `mod.rs` — exports + `ISRG_ROOTS` slice
- [x] `x1.rs` — ISRG Root X1
- [x] `x2.rs` — ISRG Root X2

### Create files — `store/digicert/`

- [x] `mod.rs` — exports + `DIGICERT_ROOTS` slice
- [x] `global.rs` — DigiCert Global Root CA
- [x] `global_g2.rs` — DigiCert Global Root G2
- [x] `global_g3.rs` — DigiCert Global Root G3
- [x] `high_assurance_ev.rs` — DigiCert High Assurance EV

### Create files — `store/amazon/`

- [x] `mod.rs` — exports + `AMAZON_ROOTS` slice
- [x] `root_1.rs` — Amazon Root CA 1
- [x] `root_2.rs` — Amazon Root CA 2
- [x] `root_3.rs` — Amazon Root CA 3
- [x] `root_4.rs` — Amazon Root CA 4

### Create files — `store/google/`

- [x] `mod.rs` — exports + `GOOGLE_ROOTS` slice
- [x] `gts_r1.rs` — GTS Root R1
- [x] `gts_r2.rs` — GTS Root R2
- [x] `gts_r3.rs` — GTS Root R3
- [x] `gts_r4.rs` — GTS Root R4

### Create files — `store/globalsign/`

- [x] `mod.rs` — exports + `GLOBALSIGN_ROOTS` slice
- [x] `r1.rs` — GlobalSign Root CA R1
- [x] `r3.rs` — GlobalSign Root CA R3
- [x] `ecc_r5.rs` — GlobalSign ECC Root CA R5

### Create files — `store/entrust/`

- [x] `mod.rs` — exports + `ENTRUST_ROOTS` slice
- [x] `starfield_g2.rs` — Starfield Root CA G2
- [x] `godaddy_g2.rs` — Go Daddy Root CA G2
- [x] `entrust_g2.rs` — Entrust Root CA G2
- [x] `entrust_ec1.rs` — Entrust Root CA EC1
- [x] `quovadis_2.rs` — QuoVadis Root CA 2
- [x] `actalis.rs` — Actalis Auth Root CA

### Create files — `store/microsoft/`

- [x] `mod.rs` — exports + `MICROSOFT_ROOTS` slice
- [x] `rsa_2017.rs` — Microsoft RSA Root CA 2017
- [x] `ecc_2017.rs` — Microsoft ECC Root CA 2017

### Create files — `store/comodo/`

- [x] `mod.rs` — exports + `COMODO_ROOTS` slice
- [x] `rsa.rs` — COMODO RSA CA
- [x] `usertrust_rsa.rs` — USERTrust RSA CA
- [x] `usertrust_ecc.rs` — USERTrust ECC CA

### Rewrite `store/mod.rs`

- [x] Import all 8 operator mods
- [x] Assemble `TRUSTED_ROOT_GROUPS` array
- [x] Exports only, no logic

### Verify Phase 1

- [x] `cargo check` passes
- [x] `trusted_root_count()` still returns 26
- [x] Every `.rs` file ≤ 75 lines
- [x] `grep -r "^//" store/` returns empty
- [x] Every `mod.rs` is exports only

---

## Phase 2: Update Python Tool

### Edit `tools/extract_root_cas.py`

- [x] Add `--source <pem-file>` arg to read from PEM bundle
- [x] Add `--output-dir <dir>` arg for output directory
- [x] Output one file per CA (never multi-CA files)
- [x] Zero comments in generated files
- [x] Zero license headers in generated files
- [x] Auto-generate `mod.rs` per operator directory
- [x] Auto-generate top-level `store/mod.rs`
- [x] Output `MANIFEST.toml` with all CA metadata
- [x] Enforce 75-line max per generated file
- [x] Exclusion list: CNNIC, Symantec, WoSign, StartCom, expired

### Generated file template (per CA)

```rust
use super::super::super::types::TrustedRootCa;

pub static ROOT: TrustedRootCa = TrustedRootCa {
    name: "...",
    subject_der: &[ ... ],
    spki_der: &[ ... ],
    spki_sha256: [ ... ],
    ski: Some(&[ ... ]),
};
```

### Generated mod.rs template (per operator)

```rust
mod file_1;
mod file_2;

use super::super::types::TrustedRootCa;

pub static OPERATOR_ROOTS: &[TrustedRootCa] = &[
    file_1::ROOT,
    file_2::ROOT,
];
```

---

## Phase 3: Generate New CA Files

### Download source

- [ ] `curl -o tools/cacert.pem https://curl.se/ca/cacert.pem`

### Run tool

- [ ] `python3 tools/extract_root_cas.py --source tools/cacert.pem --output-dir src/network/onion/tls/root_certs/store/`

### Create 13 new operator directories

- [ ] `store/sectigo/` — 2 CAs (Sectigo R46, E46)
- [ ] `store/identrust/` — 2 CAs (Commercial, DST X3)
- [ ] `store/ssl_com/` — 3 CAs (RSA, ECC, EV RSA)
- [ ] `store/buypass/` — 2 CAs (Class 2, Class 3)
- [ ] `store/certum/` — 3 CAs (Trusted Network, TN2, EC-384)
- [ ] `store/affirmtrust/` — 4 CAs (Commercial, Networking, Premium, Premium ECC)
- [ ] `store/telia/` — 1 CA (Root v2)
- [ ] `store/swisssign/` — 2 CAs (Gold G2, Silver G2)
- [ ] `store/trustwave/` — 2 CAs (Global G2, Global ECC)
- [ ] `store/oiste/` — 2 CAs (GC, GB)
- [ ] `store/government_eu/` — 15 CAs
- [ ] `store/government_apac/` — 12 CAs
- [ ] `store/regional/` — 7 CAs

### Add new roots to existing operators

- [ ] `store/entrust/entrust_g4.rs` — Entrust Root CA G4
- [ ] `store/entrust/godaddy_class2.rs` — GoDaddy Class 2

### Update `store/mod.rs`

- [ ] Add all 13 new operator mod imports
- [ ] Add all 13 new entries to `TRUSTED_ROOT_GROUPS`

---

## Phase 4: Verification

### Compile

- [ ] `cargo check` passes (bare metal target)
- [ ] Zero errors from `root_certs/` files
- [ ] Zero warnings from `root_certs/` files

### Count

- [ ] `trusted_root_count() >= 140`

### No duplicates

- [ ] No two CAs share the same `spki_sha256`

### Line counts

- [ ] `find store/ -name "*.rs" -exec wc -l {} + | awk '$1 > 75'` returns empty

### No comments

- [ ] `grep -r "^//" store/` returns empty

### mod.rs audit

- [ ] Every `mod.rs` contains only `mod`, `use`, `pub static` statements

### Binary size

- [ ] Increase < 100KB over current

---

## Phase 5: Policy Documentation

### Create `src/network/onion/tls/root_certs/TRUST_POLICY.md`

- [ ] Source: Mozilla NSS via `https://curl.se/ca/cacert.pem`
- [ ] Update cadence: quarterly (Jan, Apr, Jul, Oct)
- [ ] Inclusion criteria: Mozilla NSS + TLS server auth bit + not distrusted + expiry > 2 years
- [ ] Exclusion list: CNNIC, Symantec, WoSign, StartCom
- [ ] Update process: download PEM → run tool → review diff → cargo check → commit

---

## File Pattern Examples

**Individual CA file** (`store/isrg/x1.rs`, ≤75 lines):

```rust
use super::super::super::types::TrustedRootCa;

pub static ROOT: TrustedRootCa = TrustedRootCa {
    name: "ISRG Root X1",
    subject_der: &[
        0x30,0x4f,0x31,0x0b,0x30,0x09, ...
    ],
    spki_der: &[
        0x30,0x82,0x02,0x22,0x30,0x0d, ...
    ],
    spki_sha256: [
        0x0b,0x9f,0xa5,0xa5,0x9e,0xed,0x71,0x5c,
        0x26,0xc1,0x02,0x0c,0x71,0x1b,0x4f,0x6e,
        0xc4,0x2d,0x58,0xb0,0x01,0x5e,0x14,0x33,
        0x7a,0x39,0xda,0xd3,0x01,0xc5,0xaf,0xc3,
    ],
    ski: Some(&[
        0x79,0xb4,0x59,0xe6,0x7b,0xb6,0xe5,0xe4,
        0x01,0x73,0x80,0x08,0x88,0xc8,0x1a,0x58,
        0xf6,0xe9,0x9b,0x6e,
    ]),
};
```

**Operator mod.rs** (`store/isrg/mod.rs`, ~10 lines):

```rust
mod x1;
mod x2;

use super::super::types::TrustedRootCa;

pub static ISRG_ROOTS: &[TrustedRootCa] = &[
    x1::ROOT,
    x2::ROOT,
];
```

**Top-level store/mod.rs** (~60 lines):

```rust
mod isrg;
mod digicert;
mod amazon;
mod google;
mod globalsign;
mod entrust;
mod microsoft;
mod comodo;
mod sectigo;
mod identrust;
mod ssl_com;
mod buypass;
mod certum;
mod affirmtrust;
mod telia;
mod swisssign;
mod trustwave;
mod oiste;
mod government_eu;
mod government_apac;
mod regional;

use super::types::TrustedRootCa;

pub static TRUSTED_ROOT_GROUPS: &[&[TrustedRootCa]] = &[
    isrg::ISRG_ROOTS,
    digicert::DIGICERT_ROOTS,
    amazon::AMAZON_ROOTS,
    google::GOOGLE_ROOTS,
    globalsign::GLOBALSIGN_ROOTS,
    entrust::ENTRUST_ROOTS,
    microsoft::MICROSOFT_ROOTS,
    comodo::COMODO_ROOTS,
    sectigo::SECTIGO_ROOTS,
    identrust::IDENTRUST_ROOTS,
    ssl_com::SSL_COM_ROOTS,
    buypass::BUYPASS_ROOTS,
    certum::CERTUM_ROOTS,
    affirmtrust::AFFIRMTRUST_ROOTS,
    telia::TELIA_ROOTS,
    swisssign::SWISSSIGN_ROOTS,
    trustwave::TRUSTWAVE_ROOTS,
    oiste::OISTE_ROOTS,
    government_eu::GOV_EU_ROOTS,
    government_apac::GOV_APAC_ROOTS,
    regional::REGIONAL_ROOTS,
];
```

---

## Sizing

| Metric | Before | After |
|--------|--------|-------|
| Root CAs | 26 | ~145 |
| Operator directories | 0 | 21 |
| Individual CA files | 0 | ~145 |
| mod.rs files | 1 | 22 |
| Max lines per file | 382 | 75 |
| Total source lines | ~1,547 | ~8,500 |
| Binary DER data | ~15KB | ~90KB |
| HTTPS coverage | ~90-95% | ~99.9% |

---

## Execution Order

```
Phase 1 (refactor existing) → cargo check → Phase 2 (tooling) → Phase 3 (generate) → Phase 4 (verify) → Phase 5 (policy)
```
