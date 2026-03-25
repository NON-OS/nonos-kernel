#!/usr/bin/env python3
"""
Extract root CA certificate data and generate Rust TrustedRootCa source files.

Reads certificates from:
  1. System root CA store (macOS Keychain / OpenSSL trust store)
  2. TLS connections to well-known servers (for intermediates)

Matches each certificate's SPKI SHA-256 against the existing NONOS trust store
entries, and generates Rust source with full DER-encoded fields.

Usage:
    python3 tools/extract_root_cas.py

Output:
    Prints Rust source to stdout (redirect to appropriate store file).
    Also writes individual group files to tools/generated_store/.
"""

import hashlib
import os
import socket
import ssl
import struct
import sys
from collections import defaultdict
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtensionOID

# ---------------------------------------------------------------------------
# Our existing SPKI SHA-256 hashes grouped by store file
# ---------------------------------------------------------------------------

STORE_GROUPS = {
    "isrg": {
        "static_name": "ISRG_ROOTS",
        "entries": [
            ("ISRG Root X1", bytes([0x0b,0x9f,0xa5,0xa5,0x9e,0xed,0x71,0x5c,0x26,0xc1,0x02,0x0c,0x71,0x1b,0x4f,0x6e,0xc4,0x2d,0x58,0xb0,0x01,0x5e,0x14,0x33,0x7a,0x39,0xda,0xd3,0x01,0xc5,0xaf,0xc3])),
            ("ISRG Root X2", bytes([0x76,0x21,0x95,0xc2,0x25,0x58,0x6e,0xe6,0xc0,0x23,0x74,0x56,0xe2,0x10,0x7d,0xc5,0x4f,0x1e,0xfc,0x21,0xf6,0x1a,0x79,0x2e,0xbd,0x51,0x59,0x13,0xcc,0xe6,0x83,0x32])),
        ],
    },
    "digicert": {
        "static_name": "DIGICERT_ROOTS",
        "entries": [
            ("DigiCert Global Root CA", bytes([0xaf,0xf9,0x88,0x90,0x6d,0xde,0x12,0x95,0x5d,0x9b,0xeb,0xbf,0x92,0x8f,0xdc,0xc3,0x1c,0xce,0x32,0x8d,0x5b,0x93,0x84,0xf2,0x1c,0x89,0x41,0xca,0x26,0xe2,0x03,0x91])),
            ("DigiCert Global Root G2", bytes([0x8b,0xb5,0x93,0xa9,0x3b,0xe1,0xd0,0xe8,0xa8,0x22,0xbb,0x88,0x7c,0x54,0x78,0x90,0xc3,0xe7,0x06,0xaa,0xd2,0xda,0xb7,0x62,0x54,0xf9,0x7f,0xb3,0x6b,0x82,0xfc,0x26])),
            ("DigiCert Global Root G3", bytes([0xb9,0x4c,0x19,0x83,0x00,0xce,0xc5,0xc0,0x57,0xad,0x07,0x27,0xb7,0x0b,0xbe,0x91,0x81,0x69,0x92,0x25,0x64,0x39,0xa7,0xb3,0x2f,0x45,0x98,0x11,0x9d,0xda,0x9c,0x97])),
        ],
    },
    "globalsign": {
        "static_name": "GLOBALSIGN_ROOTS",
        "entries": [
            ("GlobalSign Root CA R1", bytes([0x2b,0xce,0xe8,0x58,0x15,0x8c,0xf5,0x46,0x5f,0xc9,0xd7,0x6f,0x0d,0xfa,0x31,0x2f,0xef,0x25,0xa4,0xdc,0xa8,0x50,0x1d,0xa9,0xb4,0x6b,0x67,0xd1,0xfb,0xfa,0x1b,0x64])),
            ("GlobalSign Root CA R3", bytes([0x70,0x6b,0xb1,0x01,0x7c,0x85,0x5c,0x59,0x16,0x9b,0xad,0x5c,0x17,0x81,0xcf,0x59,0x7f,0x12,0xd2,0xca,0xd2,0xf6,0x3d,0x1a,0x4a,0xa3,0x74,0x93,0x80,0x0f,0xfb,0x80])),
            ("GlobalSign ECC Root CA R5", bytes([0x7e,0x0e,0xad,0x76,0xbb,0x68,0x19,0xdc,0x2f,0x54,0x51,0x1a,0x84,0x35,0x4f,0x6e,0x8b,0x30,0x7b,0x9d,0xd8,0x20,0x58,0xea,0x6c,0x00,0x4f,0x01,0xd9,0xdd,0xa5,0xdf])),
        ],
    },
    "amazon": {
        "static_name": "AMAZON_ROOTS",
        "entries": [
            ("Amazon Root CA 1", bytes([0xfb,0xe3,0x01,0x80,0x31,0xf9,0x58,0x6b,0xcb,0xf4,0x17,0x27,0xe4,0x17,0xb7,0xd1,0xc4,0x5c,0x2f,0x47,0xf9,0x3b,0xe3,0x72,0xa1,0x7b,0x96,0xb5,0x07,0x57,0xd5,0xa2])),
            ("Amazon Root CA 2", bytes([0x7f,0x42,0x96,0xfc,0x5b,0x6a,0x4e,0x3b,0x35,0xd3,0xc3,0x69,0x62,0x3e,0x36,0x4a,0xb1,0xaf,0x38,0x1d,0x8f,0xa7,0x12,0x15,0x33,0xc9,0xd6,0xc6,0x33,0xea,0x24,0x61])),
            ("Amazon Root CA 3", bytes([0x36,0xab,0xc3,0x26,0x56,0xac,0xfc,0x64,0x5c,0x61,0xb7,0x16,0x13,0xc4,0xbf,0x21,0xc7,0x87,0xf5,0xca,0xbb,0xee,0x48,0x34,0x8d,0x58,0x59,0x78,0x03,0xd7,0xab,0xc9])),
            ("Amazon Root CA 4", bytes([0xf7,0xec,0xde,0xd5,0xc6,0x60,0x47,0xd2,0x8e,0xd6,0x46,0x6b,0x54,0x3c,0x40,0xe0,0x74,0x3a,0xbe,0x81,0xd1,0x09,0x25,0x4d,0xcf,0x84,0x5d,0x4c,0x2c,0x78,0x53,0xc5])),
        ],
    },
    "google": {
        "static_name": "GOOGLE_ROOTS",
        "entries": [
            ("GTS Root R1", bytes([0x87,0x1a,0x91,0x94,0xf4,0xee,0xd5,0xb3,0x12,0xff,0x40,0xc8,0x4c,0x1d,0x52,0x4a,0xed,0x2f,0x77,0x8b,0xbf,0xf2,0x5f,0x13,0x8c,0xf8,0x1f,0x68,0x0a,0x7a,0xdc,0x67])),
            ("GTS Root R2", bytes([0x55,0xf7,0x7d,0xe4,0x1c,0x03,0x79,0x24,0x28,0xf8,0xd5,0x18,0xc5,0x51,0x04,0x22,0x5b,0xe4,0x3a,0x55,0x98,0xd9,0x26,0xa5,0x28,0xad,0x65,0x3e,0x1c,0xce,0xc7,0xbf])),
            ("GTS Root R3", bytes([0x41,0x79,0xed,0xd9,0x81,0xef,0x74,0x74,0x77,0xb4,0x96,0x26,0x40,0x8a,0xf4,0x3d,0xaa,0x2c,0xa7,0xab,0x7f,0x9e,0x08,0x2c,0x10,0x60,0xf8,0x40,0x96,0x77,0x43,0x48])),
            ("GTS Root R4", bytes([0x98,0x47,0xe5,0x65,0x3e,0x5e,0x9e,0x84,0x75,0x16,0xe5,0xcb,0x81,0x86,0x06,0xaa,0x75,0x44,0xa1,0x9b,0xe6,0x7f,0xd7,0x36,0x6d,0x50,0x69,0x88,0xe8,0xd8,0x43,0x47])),
        ],
    },
    "entrust": {
        "static_name": "ENTRUST_ROOTS",
        "entries": [
            ("Starfield Root CA G2", bytes([0x80,0x8d,0x68,0xb3,0xfa,0xb4,0x88,0x4a,0x5f,0x97,0x1a,0xce,0x7d,0x10,0x55,0x0d,0x7a,0x95,0xa1,0x63,0x77,0x4f,0x3e,0xc3,0x6a,0xff,0xfb,0x21,0x3f,0xbe,0x4c,0x74])),
            ("Go Daddy Root CA G2", bytes([0x2a,0x8f,0x2d,0x8a,0xf0,0xeb,0x12,0x38,0x98,0xf7,0x4c,0x86,0x6a,0xc3,0xfa,0x66,0x90,0x54,0xe2,0x3c,0x17,0xbc,0x7a,0x95,0xbd,0x02,0x34,0x19,0x2d,0xc6,0x35,0xd0])),
            ("Entrust Root CA G2", bytes([0x76,0xee,0x85,0x90,0x37,0x4c,0x71,0x54,0x37,0xbb,0xca,0x6b,0xba,0x60,0x28,0xea,0xdd,0xe2,0xdc,0x6d,0xbb,0xb8,0xc3,0xf6,0x10,0xe8,0x51,0xf1,0x1d,0x1a,0xb7,0xf5])),
            ("Entrust Root CA EC1", bytes([0xfe,0xa2,0xb7,0xd6,0x45,0xfb,0xa7,0x3d,0x75,0x3c,0x1e,0xc9,0xa7,0x87,0x0c,0x40,0xe1,0xf7,0xb0,0xc5,0x61,0xe9,0x27,0xb9,0x85,0xbf,0x71,0x18,0x66,0xe3,0x6f,0x22])),
            ("QuoVadis Root CA 2", bytes([0x4a,0x49,0xed,0xbd,0x2f,0x8f,0x82,0x30,0xbd,0x55,0x92,0xb3,0x13,0x57,0x3f,0xe1,0xc1,0x72,0xa4,0x5f,0xa9,0x80,0x11,0xcc,0x1e,0xdd,0xbb,0x36,0xad,0xe3,0xfc,0xe5])),
            ("Microsoft RSA Root CA 2017", bytes([0xb2,0xf7,0x29,0x8b,0x52,0xbf,0x2c,0x3c,0xac,0x4d,0xdf,0xe7,0x2d,0xe4,0xd6,0x82,0xac,0x58,0x95,0x75,0x95,0x98,0x2f,0x2b,0x62,0x30,0x1a,0xf5,0x97,0xc6,0x99,0xc5])),
            ("Microsoft ECC Root CA 2017", bytes([0x35,0xf5,0x3c,0xe1,0x26,0x46,0x11,0xe0,0x33,0x40,0xfe,0x37,0xe1,0xec,0x7d,0x4c,0xc9,0x86,0xc5,0x61,0x3d,0xca,0x70,0xfd,0x04,0xaa,0x44,0x54,0x5f,0x2d,0xaf,0x28])),
            ("Actalis Auth Root CA", bytes([0x25,0xd4,0x91,0x3c,0xf5,0x87,0x09,0x74,0x14,0xd2,0x9d,0x26,0xf6,0xc1,0xb1,0x94,0x2c,0xd6,0xd6,0x4e,0xaf,0x45,0xd0,0xfc,0xf8,0x15,0x26,0xad,0xba,0x96,0xd3,0x24])),
        ],
    },
    "others": {
        "static_name": "OTHER_ROOTS",
        "entries": [
            ("Baltimore CyberTrust Root", bytes([0x63,0xd9,0xaf,0x9b,0x47,0xb1,0x06,0x4d,0x49,0xa1,0x0e,0x7b,0x7f,0xd5,0x66,0xdb,0xc8,0xca,0xa3,0x99,0x45,0x9b,0xfc,0x28,0x29,0xc5,0x71,0xad,0x8c,0x6e,0xf3,0x4a])),
            ("COMODO RSA CA", bytes([0x82,0xb5,0xf8,0x4d,0xaf,0x47,0xa5,0x9c,0x7a,0xb5,0x21,0xe4,0x98,0x2a,0xef,0xa4,0x0a,0x53,0x40,0x6a,0x3a,0xec,0x26,0x03,0x9e,0xfa,0x6b,0x2e,0x0e,0x72,0x44,0xc1])),
            ("USERTrust RSA CA", bytes([0xc7,0x84,0x33,0x3d,0x20,0xbc,0xd7,0x42,0xb9,0xfd,0xc3,0x23,0x6f,0x4e,0x50,0x9b,0x89,0x37,0x07,0x0e,0x73,0x06,0x7e,0x25,0x4d,0xd3,0xbf,0x9c,0x45,0xbf,0x4d,0xde])),
            ("USERTrust ECC CA", bytes([0x20,0x21,0x91,0x7e,0x98,0x26,0x39,0x45,0xc8,0x59,0xc4,0x3f,0x1d,0x73,0xcb,0x41,0x39,0x05,0x3c,0x41,0x4f,0xa0,0x3c,0xa3,0xbc,0x7e,0xe8,0x86,0x14,0x29,0x8f,0x3b])),
        ],
    },
}

INTERMEDIATE_GROUPS = {
    "letsencrypt_intermediates": {
        "static_name": "LETSENCRYPT_INTERMEDIATES",
        "entries": [
            ("Let's Encrypt R10", bytes([0x2b,0xba,0xd9,0x3a,0xb5,0xc7,0x92,0x79,0xec,0x12,0x15,0x07,0xf2,0x72,0xcb,0xe0,0xc6,0x64,0x7a,0x3a,0xae,0x52,0xe2,0x2f,0x38,0x8a,0xfa,0xb4,0x26,0xb4,0xad,0xba])),
            ("Let's Encrypt R11", bytes([0x6d,0xda,0xc1,0x86,0x98,0xf7,0xf1,0xf7,0xe1,0xc6,0x9b,0x9b,0xce,0x42,0x0d,0x97,0x4a,0xc6,0xf9,0x4c,0xa8,0xb2,0xc7,0x61,0x70,0x16,0x23,0xf9,0x9c,0x76,0x7d,0xc7])),
            ("Let's Encrypt R13", bytes([0x02,0x54,0x90,0x86,0x0b,0x49,0x8a,0xb7,0x3c,0x6a,0x12,0xf2,0x7a,0x49,0xad,0x5f,0xe2,0x30,0xfa,0xfe,0x3a,0xc8,0xf6,0x11,0x2c,0x9b,0x7d,0x0a,0xad,0x46,0x94,0x1d])),
            ("Let's Encrypt R14", bytes([0xf1,0x64,0x7a,0x5e,0xe3,0xef,0xac,0x54,0xc8,0x92,0xe9,0x30,0x58,0x4f,0xe4,0x79,0x79,0xb7,0xac,0xd1,0xc7,0x6c,0x12,0x71,0xbc,0xa1,0xc5,0x07,0x6d,0x86,0x98,0x88])),
            ("Let's Encrypt E5", bytes([0x35,0x86,0xd4,0xec,0xf0,0x70,0x57,0x8c,0xbd,0x27,0xae,0xdc,0xe2,0x0b,0x96,0x4e,0x48,0xbc,0x14,0x9f,0xae,0xb9,0xda,0xd7,0x2f,0x46,0xb8,0x57,0x86,0x91,0x72,0xb8])),
            ("Let's Encrypt E6", bytes([0xd0,0x16,0xe1,0xfe,0x31,0x19,0x48,0xac,0xa6,0x4f,0x2d,0xe4,0x4c,0xe8,0x6c,0x9a,0x51,0xca,0x04,0x1d,0xf6,0x10,0x3b,0xb5,0x2a,0x88,0xeb,0x3f,0x76,0x1f,0x57,0xd7])),
            ("Let's Encrypt E7", bytes([0xcb,0xbc,0x55,0x9b,0x44,0xd5,0x24,0xd6,0xa1,0x32,0xbd,0xac,0x67,0x27,0x44,0xda,0x34,0x07,0xf1,0x2a,0xae,0x5d,0x5f,0x72,0x2c,0x5f,0x6c,0x79,0x13,0x87,0x1c,0x75])),
            ("Let's Encrypt E8", bytes([0x88,0x5b,0xf0,0x57,0x22,0x52,0xc6,0x74,0x1d,0xc9,0xa5,0x2f,0x50,0x44,0x48,0x7f,0xef,0x2a,0x93,0xb8,0x11,0xcd,0xed,0xfa,0xd7,0x62,0x4c,0xc2,0x83,0xb7,0xcd,0xd5])),
            ("Let's Encrypt E9", bytes([0xf1,0x44,0x0a,0x9b,0x76,0xe1,0xe4,0x1e,0x53,0xa4,0xcb,0x46,0x13,0x29,0xbf,0x63,0x37,0xb4,0x19,0x72,0x6b,0xe5,0x13,0xe4,0x2e,0x19,0xf1,0xc6,0x91,0xc5,0xd4,0xb2])),
        ],
    },
    "digicert_intermediates": {
        "static_name": "DIGICERT_INTERMEDIATES",
        "entries": [
            ("DigiCert G2 TLS RSA SHA256 2020 CA1", bytes([0x59,0xe7,0x38,0xe6,0x74,0x22,0x17,0x02,0xaf,0x1e,0xdb,0x87,0xc5,0x20,0x0c,0x1a,0x4b,0x75,0xf6,0x4f,0xae,0x3d,0x2c,0x3d,0x26,0x51,0x24,0xc6,0x1b,0xd8,0x3c,0x79])),
            ("DigiCert G3 TLS ECC SHA384 2020 CA1", bytes([0xa8,0x14,0x63,0x66,0x63,0xa6,0x91,0x23,0x49,0x2f,0x4a,0x7b,0xd3,0x37,0xa4,0xee,0x87,0x52,0x23,0x3a,0xac,0xfe,0x6b,0x91,0xe0,0x99,0x3d,0xc5,0x8c,0x82,0x3f,0xe1])),
            ("DigiCert Global CA G2", bytes([0x9e,0x33,0x78,0xad,0x11,0xbe,0xdb,0x67,0x4d,0x5c,0x08,0xbe,0xc9,0xbf,0x1e,0xdd,0x43,0x32,0xa6,0x0c,0xcf,0x50,0xf1,0xe5,0xbf,0x8f,0x9f,0xa1,0x42,0xf0,0x97,0x58])),
        ],
    },
    "sectigo_intermediates": {
        "static_name": "SECTIGO_INTERMEDIATES",
        "entries": [
            ("Sectigo Public Server Auth Root E46", bytes([0xb0,0xb5,0x63,0x35,0x46,0x85,0x61,0xf5,0xbb,0x9f,0xa1,0x2d,0x80,0x17,0x84,0xa6,0x33,0xa5,0x72,0x70,0x5d,0x34,0xf3,0x2b,0x64,0x34,0x45,0xdf,0xa8,0xb0,0x05,0xd1])),
        ],
    },
    "microsoft_intermediates": {
        "static_name": "MICROSOFT_INTERMEDIATES",
        "entries": [
            ("Microsoft TLS RSA Root G2", bytes([0x4b,0x03,0xc9,0x96,0x6c,0x86,0x3b,0x2c,0x00,0x8a,0x95,0xa5,0xed,0x92,0x54,0x07,0x04,0x48,0xc7,0xb2,0x19,0xd2,0x83,0x10,0x2f,0x6a,0x6c,0x5b,0x6e,0x8e,0x2a,0xcd])),
        ],
    },
}

# Servers to connect to for harvesting intermediate certificates
HARVEST_SERVERS = [
    "letsencrypt.org",
    "www.google.com",
    "www.amazon.com",
    "www.digicert.com",
    "www.microsoft.com",
    "www.cloudflare.com",
    "github.com",
    "sectigo.com",
    # Additional servers for broader intermediate coverage
    "www.reddit.com",
    "www.wikipedia.org",
    "www.mozilla.org",
    "www.python.org",
    "www.rust-lang.org",
    "www.npmjs.com",
    "crates.io",
    "docs.rs",
    "www.hetzner.com",
    "www.fastly.com",
    "www.akamai.com",
    "www.netlify.com",
    "www.vercel.com",
    "www.docker.com",
    "www.ubuntu.com",
    "www.debian.org",
    "www.archlinux.org",
    "www.paypal.com",
    "www.stripe.com",
    "www.twitch.tv",
    "www.spotify.com",
    "www.dropbox.com",
    "www.linkedin.com",
    "www.facebook.com",
    "www.apple.com",
    "www.eff.org",
    "www.fsf.org",
]

# ---------------------------------------------------------------------------
# Certificate extraction helpers
# ---------------------------------------------------------------------------

def extract_cert_data(cert):
    """Extract Subject DN DER, SPKI DER, SPKI SHA-256, and SKI from a
    cryptography x509.Certificate object."""
    spki_der = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    spki_sha256 = hashlib.sha256(spki_der).digest()
    subject_der = cert.subject.public_bytes()

    ski = None
    try:
        ski_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        ski = ski_ext.value.digest
    except x509.ExtensionNotFound:
        pass

    return {
        "subject_der": subject_der,
        "spki_der": spki_der,
        "spki_sha256": spki_sha256,
        "ski": ski,
        "subject_cn": _get_cn(cert),
    }


def _get_cn(cert):
    """Get the Common Name from a certificate's subject."""
    try:
        cns = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if cns:
            return cns[0].value
    except Exception:
        pass
    return "<unknown>"


def collect_system_certs():
    """Collect certificates from certifi bundle and system trust store."""
    result = {}  # spki_sha256 -> cert_data

    # Try certifi first (Mozilla's CA bundle, most reliable on macOS)
    try:
        import certifi
        cafile = certifi.where()
        with open(cafile, "rb") as f:
            pem_data = f.read()
        certs = x509.load_pem_x509_certificates(pem_data)
        for cert in certs:
            try:
                data = extract_cert_data(cert)
                result[data["spki_sha256"]] = data
            except Exception as e:
                print(f"  [WARN] Failed to extract cert data: {e}", file=sys.stderr)
        print(f"  Loaded {len(result)} certificates from certifi bundle", file=sys.stderr)
    except ImportError:
        print("  [WARN] certifi not available, trying system store", file=sys.stderr)

    # Also try system SSL context (may add additional certs)
    try:
        ctx = ssl.create_default_context()
        # On macOS, try loading certifi certs into context
        try:
            import certifi
            ctx = ssl.create_default_context(cafile=certifi.where())
        except ImportError:
            pass
        certs_der = ctx.get_ca_certs(binary_form=True)
        added = 0
        for der_bytes in certs_der:
            try:
                cert = x509.load_der_x509_certificate(der_bytes)
                data = extract_cert_data(cert)
                if data["spki_sha256"] not in result:
                    result[data["spki_sha256"]] = data
                    added += 1
            except Exception:
                pass
        if added > 0:
            print(f"  +{added} additional certs from system SSL context", file=sys.stderr)
    except Exception as e:
        print(f"  [WARN] System SSL context failed: {e}", file=sys.stderr)

    print(f"  Total: {len(result)} certificates from trust stores", file=sys.stderr)
    return result


def collect_tls_chain_certs(hostname, port=443):
    """Connect to a server and collect all certificates in the TLS chain."""
    result = {}
    try:
        ctx = ssl.create_default_context()
        # Use certifi bundle on macOS where system certs may not load
        try:
            import certifi
            ctx = ssl.create_default_context(cafile=certifi.where())
        except ImportError:
            pass
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                chain_der = ssock.get_verified_chain()
                if chain_der is None:
                    # Fallback: get just the peer cert
                    peer_der = ssock.getpeercert(binary_form=True)
                    if peer_der:
                        chain_der = [peer_der]
                    else:
                        chain_der = []

                for cert_der in chain_der:
                    # Python 3.13: get_verified_chain returns list of bytes
                    if isinstance(cert_der, bytes):
                        der_bytes = cert_der
                    elif hasattr(cert_der, 'public_bytes'):
                        try:
                            der_bytes = cert_der.public_bytes(ssl._ASN1_ENCODING_RULES_DER)
                        except Exception:
                            continue
                    else:
                        continue

                    try:
                        cert = x509.load_der_x509_certificate(der_bytes)
                        data = extract_cert_data(cert)
                        result[data["spki_sha256"]] = data
                    except Exception as e:
                        print(f"  [WARN] Failed to parse chain cert from {hostname}: {e}", file=sys.stderr)

    except Exception as e:
        print(f"  [WARN] TLS connection to {hostname} failed: {e}", file=sys.stderr)

    # Also try openssl s_client for additional certs not in verified chain
    try:
        import subprocess
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", f"{hostname}:{port}",
             "-servername", hostname, "-showcerts"],
            input=b"",
            capture_output=True,
            timeout=10,
        )
        pem_certs = _extract_pems_from_openssl(proc.stdout)
        for pem_bytes in pem_certs:
            try:
                cert = x509.load_pem_x509_certificate(pem_bytes)
                data = extract_cert_data(cert)
                if data["spki_sha256"] not in result:
                    result[data["spki_sha256"]] = data
            except Exception:
                pass
    except Exception:
        pass

    return result


def _extract_pems_from_openssl(output):
    """Extract PEM certificate blocks from openssl s_client output."""
    pems = []
    in_cert = False
    current = []
    for line in output.split(b"\n"):
        if b"-----BEGIN CERTIFICATE-----" in line:
            in_cert = True
            current = [line]
        elif b"-----END CERTIFICATE-----" in line and in_cert:
            current.append(line)
            pems.append(b"\n".join(current))
            in_cert = False
            current = []
        elif in_cert:
            current.append(line)
    return pems


def collect_all_certs():
    """Collect certificates from all available sources."""
    print("Collecting certificates...", file=sys.stderr)

    # 1. System trust store
    print("  Source: system trust store", file=sys.stderr)
    all_certs = collect_system_certs()

    # 2. TLS chain harvesting for intermediates
    for server in HARVEST_SERVERS:
        print(f"  Source: TLS chain from {server}", file=sys.stderr)
        chain_certs = collect_tls_chain_certs(server)
        new_count = 0
        for k, v in chain_certs.items():
            if k not in all_certs:
                all_certs[k] = v
                new_count += 1
        if new_count > 0:
            print(f"    +{new_count} new certificates", file=sys.stderr)

    print(f"  Total: {len(all_certs)} unique certificates collected", file=sys.stderr)
    return all_certs


# ---------------------------------------------------------------------------
# Rust source generation
# ---------------------------------------------------------------------------

LICENSE_HEADER = """\
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
"""


def format_bytes_rust(data, indent=8):
    """Format a byte sequence as a Rust byte array literal."""
    if data is None:
        return "None"

    prefix = " " * indent
    line_width = 12  # bytes per line
    lines = []
    for i in range(0, len(data), line_width):
        chunk = data[i:i + line_width]
        hex_vals = ",".join(f"0x{b:02x}" for b in chunk)
        lines.append(f"{prefix}{hex_vals},")

    inner = "\n".join(lines)
    return f"&[\n{inner}\n{' ' * (indent - 4)}]"


def format_spki_sha256_rust(data, indent=8):
    """Format a 32-byte SPKI SHA-256 hash as a Rust array literal."""
    prefix = " " * indent
    parts = []
    for i in range(0, 32, 8):
        chunk = data[i:i + 8]
        hex_vals = ",".join(f"0x{b:02x}" for b in chunk)
        parts.append(f"{prefix}{hex_vals},")
    return "[\n" + "\n".join(parts) + f"\n{' ' * (indent - 4)}]"


def generate_entry_rust(name, cert_data, indent=4):
    """Generate a single TrustedRootCa entry."""
    prefix = " " * indent
    inner = " " * (indent + 4)

    subject = format_bytes_rust(cert_data["subject_der"], indent + 8)
    spki = format_bytes_rust(cert_data["spki_der"], indent + 8)
    sha256 = format_spki_sha256_rust(cert_data["spki_sha256"], indent + 8)

    ski_val = "None"
    if cert_data.get("ski") is not None:
        ski_bytes = format_bytes_rust(cert_data["ski"], indent + 8)
        ski_val = f"Some({ski_bytes})"

    return f"""{prefix}TrustedRootCa {{
{inner}name: "{name}",
{inner}subject_der: {subject},
{inner}spki_der: {spki},
{inner}spki_sha256: {sha256},
{inner}ski: {ski_val},
{prefix}}},"""


def generate_store_file(group_key, group_info, cert_lookup, is_intermediate=False):
    """Generate a complete Rust store file for a group."""
    static_name = group_info["static_name"]
    entries = group_info["entries"]

    lines = [LICENSE_HEADER]

    if is_intermediate:
        lines.append("//! Full certificate data for widely-deployed intermediate CAs.")
        lines.append("//!")
        lines.append("//! Most TLS servers send [leaf, intermediate(s)] without the root CA.")
        lines.append("//! Since our verifier checks the topmost cert's SPKI against the trust")
        lines.append("//! store, we must include these intermediates so that chains terminating")
        lines.append("//! at a well-known intermediate are accepted.")
        lines.append("")

    lines.append("use super::super::types::TrustedRootCa;")
    lines.append("")
    lines.append(f"pub(super) static {static_name}: &[TrustedRootCa] = &[")

    found = 0
    missing = 0
    for name, spki_hash in entries:
        if spki_hash in cert_lookup:
            data = cert_lookup[spki_hash]
            lines.append(generate_entry_rust(name, data))
            found += 1
        else:
            # Missing cert — generate with empty DER fields but keep SPKI hash
            print(f"  [MISS] {name} — not found in any source", file=sys.stderr)
            fallback = {
                "subject_der": b"",
                "spki_der": b"",
                "spki_sha256": spki_hash,
                "ski": None,
            }
            lines.append(generate_entry_rust(name, fallback))
            missing += 1

    lines.append("];")
    lines.append("")

    return "\n".join(lines), found, missing


def generate_intermediates_file(cert_lookup):
    """Generate the combined intermediates.rs file."""
    lines = [LICENSE_HEADER]
    lines.append("//! Full certificate data for widely-deployed intermediate CAs.")
    lines.append("//!")
    lines.append("//! Most TLS servers send [leaf, intermediate(s)] without the root CA.")
    lines.append("//! Since our verifier checks the topmost cert's SPKI against the trust")
    lines.append("//! store, we must include these intermediates so that chains terminating")
    lines.append("//! at a well-known intermediate are accepted.")
    lines.append("")
    lines.append("use super::super::types::TrustedRootCa;")
    lines.append("")

    total_found = 0
    total_missing = 0

    for group_key, group_info in INTERMEDIATE_GROUPS.items():
        static_name = group_info["static_name"]
        entries = group_info["entries"]

        lines.append(f"pub(super) static {static_name}: &[TrustedRootCa] = &[")
        for name, spki_hash in entries:
            if spki_hash in cert_lookup:
                data = cert_lookup[spki_hash]
                lines.append(generate_entry_rust(name, data))
                total_found += 1
            else:
                print(f"  [MISS] {name} — not found in any source", file=sys.stderr)
                fallback = {
                    "subject_der": b"",
                    "spki_der": b"",
                    "spki_sha256": spki_hash,
                    "ski": None,
                }
                lines.append(generate_entry_rust(name, fallback))
                total_missing += 1
        lines.append("];")
        lines.append("")

    return "\n".join(lines), total_found, total_missing


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Collect certs from all sources
    cert_lookup = collect_all_certs()

    # Build a quick lookup of what we need vs what we have
    all_needed = {}
    for groups in [STORE_GROUPS, INTERMEDIATE_GROUPS]:
        for group_info in groups.values():
            for name, spki_hash in group_info["entries"]:
                all_needed[spki_hash] = name

    found_count = sum(1 for h in all_needed if h in cert_lookup)
    print(f"\nMatched {found_count}/{len(all_needed)} certificates", file=sys.stderr)
    for h, name in all_needed.items():
        status = "OK" if h in cert_lookup else "MISSING"
        print(f"  [{status}] {name}", file=sys.stderr)

    # Generate output directory
    out_dir = Path(__file__).parent / "generated_store"
    out_dir.mkdir(exist_ok=True)

    total_found = 0
    total_missing = 0

    # Generate root CA group files
    for group_key, group_info in STORE_GROUPS.items():
        content, found, missing = generate_store_file(
            group_key, group_info, cert_lookup
        )
        total_found += found
        total_missing += missing
        out_path = out_dir / f"{group_key}.rs"
        out_path.write_text(content)
        print(f"  Wrote {out_path} ({found} found, {missing} missing)", file=sys.stderr)

    # Generate combined intermediates file
    content, found, missing = generate_intermediates_file(cert_lookup)
    total_found += found
    total_missing += missing
    out_path = out_dir / "intermediates.rs"
    out_path.write_text(content)
    print(f"  Wrote {out_path} ({found} found, {missing} missing)", file=sys.stderr)

    print(f"\nTotal: {total_found} found, {total_missing} missing out of {len(all_needed)}", file=sys.stderr)

    if total_missing > 0:
        print("\n[!] Some certificates were not found. Their entries have empty", file=sys.stderr)
        print("    subject_der/spki_der fields. These need to be sourced manually.", file=sys.stderr)

    # Also generate store/mod.rs
    mod_content = generate_store_mod()
    (out_dir / "mod.rs").write_text(mod_content)
    print(f"  Wrote {out_dir / 'mod.rs'}", file=sys.stderr)


def generate_store_mod():
    """Generate the store/mod.rs that assembles all groups."""
    lines = [LICENSE_HEADER]
    lines.append("mod amazon;")
    lines.append("mod digicert;")
    lines.append("mod entrust;")
    lines.append("mod globalsign;")
    lines.append("mod google;")
    lines.append("mod intermediates;")
    lines.append("mod isrg;")
    lines.append("mod others;")
    lines.append("")
    lines.append("use super::types::TrustedRootCa;")
    lines.append("use amazon::AMAZON_ROOTS;")
    lines.append("use digicert::DIGICERT_ROOTS;")
    lines.append("use entrust::ENTRUST_ROOTS;")
    lines.append("use globalsign::GLOBALSIGN_ROOTS;")
    lines.append("use google::GOOGLE_ROOTS;")
    lines.append("use intermediates::{LETSENCRYPT_INTERMEDIATES, DIGICERT_INTERMEDIATES, SECTIGO_INTERMEDIATES, MICROSOFT_INTERMEDIATES};")
    lines.append("use isrg::ISRG_ROOTS;")
    lines.append("use others::OTHER_ROOTS;")
    lines.append("")
    lines.append("pub static TRUSTED_ROOT_GROUPS: &[&[TrustedRootCa]] = &[")
    lines.append("    ISRG_ROOTS,")
    lines.append("    DIGICERT_ROOTS,")
    lines.append("    GLOBALSIGN_ROOTS,")
    lines.append("    OTHER_ROOTS,")
    lines.append("    AMAZON_ROOTS,")
    lines.append("    GOOGLE_ROOTS,")
    lines.append("    ENTRUST_ROOTS,")
    lines.append("    LETSENCRYPT_INTERMEDIATES,")
    lines.append("    DIGICERT_INTERMEDIATES,")
    lines.append("    SECTIGO_INTERMEDIATES,")
    lines.append("    MICROSOFT_INTERMEDIATES,")
    lines.append("];")
    lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    main()
