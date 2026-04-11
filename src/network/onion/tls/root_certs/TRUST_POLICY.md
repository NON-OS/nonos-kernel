# Root CA Trust Store Policy — NONOS Kernel

## Source of Truth

**Mozilla NSS Root CA Program** via curl's extracted PEM bundle:
- URL: `https://curl.se/ca/cacert.pem`
- Derived from: Mozilla NSS `certdata.txt`
- Maintained by: Mozilla Foundation

## Inclusion Criteria

A root CA is included in the NONOS trust store if it meets **all** of the following:

1. **Mozilla NSS inclusion** — Must be in the Mozilla NSS root program
2. **TLS Server Authentication** — Must have the "Websites" trust bit enabled
3. **Not distrusted** — Must not be on the Mozilla distrust list
4. **Validity period** — Certificate expiry > 2 years from bundle date
5. **Not excluded** — Must not be on the NONOS exclusion list (see below)

## Exclusion List

The following CAs are **explicitly excluded** regardless of Mozilla NSS status:

| CA Name Pattern | Reason | Status |
|-----------------|--------|--------|
| CNNIC ROOT | Government control concerns | Permanent exclusion |
| China Internet Network Information Center EV | Government control concerns | Permanent exclusion |
| WoSign | Certificate misissuance history | Permanent exclusion |
| StartCom | Certificate misissuance history | Permanent exclusion |
| Symantec Class 3 Secure Server CA | Deprecated — replaced by DigiCert | Permanent exclusion |
| Baltimore CyberTrust Root | Legacy — EOL 2025 | Permanent exclusion |

## Update Cadence

**Quarterly updates** on the following schedule:

| Quarter | Month | Target Date |
|---------|-------|-------------|
| Q1 | January | First week of January |
| Q2 | April | First week of April |
| Q3 | July | First week of July |
| Q4 | October | First week of October |

Updates may occur **out-of-cycle** if:
- A root CA is compromised or distrusted by Mozilla
- Critical security vulnerabilities are discovered
- A major CA operator adds/removes roots

## Update Process

```bash
# 1. Download latest Mozilla NSS CA bundle
curl -o tools/cacert.pem https://curl.se/ca/cacert.pem

# 2. Generate new CA store
python3 tools/generate_ca_store.py tools/cacert.pem src/network/onion/tls/root_certs/store/

# 3. Review changes
git diff --stat src/network/onion/tls/root_certs/

# 4. Verify no compilation errors
make

# 5. Review MANIFEST.toml for new/removed CAs
git diff src/network/onion/tls/root_certs/MANIFEST.toml

# 6. Commit with descriptive message
git add -A src/network/onion/tls/root_certs/ tools/cacert.pem
git commit -m "tls: quarterly root CA update (YYYY-QX)"
```

## Current Statistics

| Metric | Value |
|--------|-------|
| **Total Root CAs** | 132 |
| **Operator Directories** | 21 |
| **Coverage** | ~99% of HTTPS websites |
| **Last Update** | 2026-04-11 (Phase 3 initial expansion) |
| **Source Bundle Date** | 2026-04-11 |
| **Next Scheduled Update** | 2026-07-01 (Q3) |

## Verification

After each update, the following checks are **mandatory**:

- [ ] Zero duplicate SPKI hashes
- [ ] All files ≤ 80 lines (target: ≤ 75)
- [ ] Zero comments in CA files
- [ ] Zero license headers in CA files
- [ ] All `mod.rs` files are exports-only
- [ ] `make` succeeds (kernel builds)
- [ ] No new clippy warnings in `root_certs/`

## Operator Directory Structure

```
store/
├── affirmtrust/        — AffirmTrust
├── amazon/             — Amazon Trust Services
├── buypass/            — Buypass AS
├── certum/             — Asseco / Unizeto
├── comodo/             — COMODO / Sectigo (legacy)
├── digicert/           — DigiCert Inc
├── entrust/            — Entrust, Starfield, GoDaddy, QuoVadis, Actalis
├── globalsign/         — GlobalSign
├── google/             — Google Trust Services
├── government_apac/    — TWCA, CFCA, eMudhra, SECOM, Hongkong Post
├── government_eu/      — D-Trust, T-Telesec, Certigna, FNMT, Atos, Izenpe
├── identrust/          — IdenTrust
├── isrg/               — Internet Security Research Group (Let's Encrypt)
├── microsoft/          — Microsoft Corporation
├── oiste/              — OISTE / WISeKey
├── regional/           — Certainly, ANF, TrustAsia, GDCA, E-Szigno, etc.
├── sectigo/            — Sectigo (modern roots)
├── ssl_com/            — SSL.com
├── swisssign/          — SwissSign AG
├── telia/              — Telia / TeliaSonera
└── trustwave/          — Trustwave Holdings
```

## Rationale

### Why Mozilla NSS?

- **Industry standard** — Used by Firefox, Thunderbird, LibreOffice, curl, wget
- **Rigorous vetting** — Mozilla's CA inclusion policy is public and strict
- **Active maintenance** — Mozilla actively monitors and removes distrusted CAs
- **Transparent** — All decisions are public and documented

### Why Not OS Trust Stores?

- **Fragmentation** — Windows/macOS/Linux have different trust stores
- **Platform-specific** — NONOS is `no_std` and doesn't depend on host OS
- **Slower updates** — OS vendors update CA stores less frequently
- **Government CAs** — Some OS trust stores include government CAs we exclude

### Why Exclude Certain CAs?

- **CNNIC / China Internet Network Information Center** — Government-controlled CA with history of questionable issuance practices
- **WoSign / StartCom** — Backdating certificates, SHA-1 after deprecation, ownership opacity
- **Symantec legacy** — Mass distrust after repeated validation failures (Google Chrome CT logs)

## References

- Mozilla CA Policy: https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/
- curl CA Extract: https://curl.se/docs/caextract.html
- NONOS CA Expansion Plan: `/root-ca-expansion-plan.md`
- Generation Tool: `/tools/generate_ca_store.py`
