#!/usr/bin/env python3
"""
Generate per-file root CA store from a PEM bundle (Mozilla NSS via curl).

Usage:
    curl -o tools/cacert.pem https://curl.se/ca/cacert.pem
    python3 tools/generate_ca_store.py tools/cacert.pem src/network/onion/tls/root_certs/store/
"""

import hashlib
import os
import re
import sys
import datetime
from pathlib import Path
from collections import defaultdict

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtensionOID, NameOID

EXCLUDED = {
    "CNNIC ROOT",
    "China Internet Network Information Center EV Certificates Root",
    "WoSign",
    "StartCom",
    "Symantec Class 3 Secure Server CA",
    "Baltimore CyberTrust Root",
}

ORG_TO_DIR = {
    "Internet Security Research Group": "isrg",
    "DigiCert Inc": "digicert",
    "DigiCert, Inc.": "digicert",
    "Amazon": "amazon",
    "Google Trust Services LLC": "google",
    "GlobalSign nv-sa": "globalsign",
    "Entrust, Inc.": "entrust",
    "Entrust.net": "entrust",
    "Starfield Technologies, Inc.": "entrust",
    "GoDaddy.com, Inc.": "entrust",
    "Go Daddy": "entrust",
    "Sectigo Limited": "sectigo",
    "COMODO CA Limited": "comodo",
    "The USERTRUST Network": "comodo",
    "IdenTrust": "identrust",
    "SSL Corporation": "ssl_com",
    "SSL.com": "ssl_com",
    "Buypass AS-983163327": "buypass",
    "Buypass AS": "buypass",
    "Asseco Data Systems S.A.": "certum",
    "Unizeto Technologies S.A.": "certum",
    "AffirmTrust": "affirmtrust",
    "Telia Finland Oyj": "telia",
    "TeliaSonera": "telia",
    "SwissSign AG": "swisssign",
    "Trustwave Holdings, Inc.": "trustwave",
    "WISeKey": "oiste",
    "OISTE Foundation": "oiste",
    "Microsoft Corporation": "microsoft",
    "QuoVadis Limited": "entrust",
    "Actalis S.p.A.": "entrust",
    "D-Trust GmbH": "government_eu",
    "T-Systems Enterprise Services GmbH": "government_eu",
    "Deutsche Telekom AG": "government_eu",
    "FNMT-RCM": "government_eu",
    "Agence Nationale de la Securite des Systemes d'Information": "government_eu",
    "Dhimyotis": "government_eu",
    "Certigna": "government_eu",
    "HARICA": "government_eu",
    "Atos": "government_eu",
    "Izenpe S.A.": "government_eu",
    "A-Trust Ges. f. Sicherheitssysteme im elektr. Datenverkehr GmbH": "government_eu",
    "E-Tugra EBG A.S.": "government_eu",
    "Staat der Nederlanden": "government_eu",
    "SECOM Trust Systems CO.,LTD.": "government_apac",
    "SECOM Trust.net": "government_apac",
    "TWCA": "government_apac",
    "Taiwan-CA": "government_apac",
    "China Financial Certification Authority": "government_apac",
    "eMudhra Technologies Limited": "government_apac",
    "eMudhra Inc": "government_apac",
    "KISA": "government_apac",
    "Hongkong Post": "government_apac",
    "Security Communication": "government_apac",
    "NAVER CLOUD CORP.": "government_apac",
}

STATIC_NAMES = {
    "isrg": "ISRG_ROOTS",
    "digicert": "DIGICERT_ROOTS",
    "amazon": "AMAZON_ROOTS",
    "google": "GOOGLE_ROOTS",
    "globalsign": "GLOBALSIGN_ROOTS",
    "entrust": "ENTRUST_ROOTS",
    "comodo": "COMODO_ROOTS",
    "microsoft": "MICROSOFT_ROOTS",
    "sectigo": "SECTIGO_ROOTS",
    "identrust": "IDENTRUST_ROOTS",
    "ssl_com": "SSL_COM_ROOTS",
    "buypass": "BUYPASS_ROOTS",
    "certum": "CERTUM_ROOTS",
    "affirmtrust": "AFFIRMTRUST_ROOTS",
    "telia": "TELIA_ROOTS",
    "swisssign": "SWISSSIGN_ROOTS",
    "trustwave": "TRUSTWAVE_ROOTS",
    "oiste": "OISTE_ROOTS",
    "government_eu": "GOV_EU_ROOTS",
    "government_apac": "GOV_APAC_ROOTS",
    "regional": "REGIONAL_ROOTS",
}


def extract_cert_data(cert):
    spki_der = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    spki_sha256 = hashlib.sha256(spki_der).digest()
    subject_der = cert.subject.public_bytes()
    ski = None
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        ski = ext.value.digest
    except x509.ExtensionNotFound:
        pass
    cn = ""
    try:
        cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cns:
            cn = cns[0].value
    except Exception:
        pass
    org = ""
    try:
        orgs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if orgs:
            org = orgs[0].value
    except Exception:
        pass
    return {
        "cn": cn,
        "org": org,
        "subject_der": subject_der,
        "spki_der": spki_der,
        "spki_sha256": spki_sha256,
        "ski": ski,
        "not_after": cert.not_valid_after_utc,
        "key_type": type(cert.public_key()).__name__,
    }


def is_excluded(data):
    cn = data["cn"]
    for excl in EXCLUDED:
        if excl.lower() in cn.lower():
            return True
    if data["not_after"] < datetime.datetime.now(datetime.timezone.utc):
        return True
    return False


def org_to_dir(org):
    for pattern, dirname in ORG_TO_DIR.items():
        if pattern.lower() in org.lower():
            return dirname
    return "regional"


def cn_to_filename(cn):
    safe = re.sub(r'[^a-z0-9]+', '_', cn.lower()).strip('_')
    if len(safe) > 40:
        safe = safe[:40].rstrip('_')
    return safe


def format_bytes(data, indent=8, per_line=12):
    if data is None:
        return "None"
    prefix = " " * indent
    lines = []
    for i in range(0, len(data), per_line):
        chunk = data[i:i + per_line]
        hex_vals = ",".join(f"0x{b:02x}" for b in chunk)
        lines.append(f"{prefix}{hex_vals},")
    return "&[\n" + "\n".join(lines) + f"\n{' ' * (indent - 4)}]"


def format_sha256(data, indent=8):
    prefix = " " * indent
    parts = []
    for i in range(0, 32, 8):
        chunk = data[i:i + 8]
        hex_vals = ",".join(f"0x{b:02x}" for b in chunk)
        parts.append(f"{prefix}{hex_vals},")
    return "[\n" + "\n".join(parts) + f"\n{' ' * (indent - 4)}]"


def generate_ca_file(data, depth=3):
    super_path = "super::" * depth
    ski_str = "None"
    if data["ski"] is not None:
        ski_bytes = format_bytes(data["ski"], 8)
        ski_str = f"Some({ski_bytes})"
    per_line = 12
    estimated = 6 + len(data["subject_der"]) // (per_line * 1) + len(data["spki_der"]) // (per_line * 1) + 8
    if estimated > 70:
        per_line = 14
    lines = []
    lines.append(f"use {super_path}types::TrustedRootCa;")
    lines.append("")
    lines.append("pub static ROOT: TrustedRootCa = TrustedRootCa {")
    lines.append(f'    name: "{data["cn"]}",')
    lines.append(f"    subject_der: {format_bytes(data['subject_der'], 8, per_line)},")
    lines.append(f"    spki_der: {format_bytes(data['spki_der'], 8, per_line)},")
    lines.append(f"    spki_sha256: {format_sha256(data['spki_sha256'], 8)},")
    lines.append(f"    ski: {ski_str},")
    lines.append("};")
    return "\n".join(lines) + "\n"


def generate_operator_mod(filenames, static_name, depth=2):
    super_path = "super::" * depth
    lines = []
    for fn in sorted(filenames):
        lines.append(f"mod {fn};")
    lines.append("")
    lines.append(f"use {super_path}types::TrustedRootCa;")
    lines.append("")
    lines.append(f"pub static {static_name}: &[TrustedRootCa] = &[")
    for fn in sorted(filenames):
        lines.append(f"    {fn}::ROOT,")
    lines.append("];")
    return "\n".join(lines) + "\n"


def generate_top_mod(operators):
    lines = []
    for op in sorted(operators):
        lines.append(f"mod {op};")
    lines.append("")
    lines.append("use super::types::TrustedRootCa;")
    lines.append("")
    lines.append("pub static TRUSTED_ROOT_GROUPS: &[&[TrustedRootCa]] = &[")
    for op in sorted(operators):
        static = STATIC_NAMES.get(op, f"{op.upper()}_ROOTS")
        lines.append(f"    {op}::{static},")
    lines.append("];")
    return "\n".join(lines) + "\n"


def generate_manifest(all_data):
    lines = ["# Root CA Trust Store Manifest", "# Generated from Mozilla NSS PEM bundle", ""]
    for dirname, cas in sorted(all_data.items()):
        lines.append(f"[{dirname}]")
        for data in sorted(cas, key=lambda d: d["cn"]):
            expiry = data["not_after"].strftime("%Y-%m-%d")
            sha = data["spki_sha256"].hex()[:16]
            lines.append(f'  "{data["cn"]}" = {{ key = "{data["key_type"]}", expires = "{expiry}", spki_prefix = "{sha}" }}')
        lines.append("")
    return "\n".join(lines) + "\n"


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <cacert.pem> <output-dir>", file=sys.stderr)
        sys.exit(1)

    pem_path = sys.argv[1]
    out_dir = Path(sys.argv[2])

    with open(pem_path, "rb") as f:
        pem_data = f.read()

    certs = x509.load_pem_x509_certificates(pem_data)
    print(f"Loaded {len(certs)} certificates from {pem_path}", file=sys.stderr)

    groups = defaultdict(list)
    skipped = 0
    for cert in certs:
        data = extract_cert_data(cert)
        if is_excluded(data):
            print(f"  SKIP: {data['cn']}", file=sys.stderr)
            skipped += 1
            continue
        dirname = org_to_dir(data["org"])
        groups[dirname].append(data)

    print(f"Included: {sum(len(v) for v in groups.values())}, Skipped: {skipped}", file=sys.stderr)

    used_filenames = defaultdict(dict)
    for dirname, cas in groups.items():
        dir_path = out_dir / dirname
        dir_path.mkdir(parents=True, exist_ok=True)
        filenames = []
        for data in cas:
            fn = cn_to_filename(data["cn"])
            if fn in filenames:
                fn = fn + "_2"
            filenames.append(fn)
            content = generate_ca_file(data)
            line_count = content.count("\n")
            if line_count > 75:
                content = generate_ca_file(data)
                print(f"  WARN: {dirname}/{fn}.rs is {line_count} lines", file=sys.stderr)
            (dir_path / f"{fn}.rs").write_text(content)
        static_name = STATIC_NAMES.get(dirname, f"{dirname.upper()}_ROOTS")
        mod_content = generate_operator_mod(filenames, static_name)
        (dir_path / "mod.rs").write_text(mod_content)
        used_filenames[dirname] = filenames
        print(f"  {dirname}/: {len(cas)} CAs", file=sys.stderr)

    top_mod = generate_top_mod(groups.keys())
    (out_dir / "mod.rs").write_text(top_mod)

    manifest = generate_manifest(groups)
    (out_dir.parent / "MANIFEST.toml").write_text(manifest)

    total = sum(len(v) for v in groups.values())
    print(f"\nGenerated {total} CA files across {len(groups)} directories", file=sys.stderr)


if __name__ == "__main__":
    main()
