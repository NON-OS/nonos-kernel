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

use crate::network::onion::OnionError;
use crate::network::onion::nonos_crypto::X509Certificate;
use crate::crypto::hash::unified::sha256;
use crate::sys::serial;
use super::store::TRUSTED_ROOT_GROUPS;
use super::types::TrustedRootCa;
use alloc::vec::Vec;

pub fn is_trusted_root(cert: &X509Certificate) -> bool {
    let spki_hash = sha256(&cert.public_key.raw_spki);
    for group in TRUSTED_ROOT_GROUPS {
        for root in *group {
            if root.spki_sha256 == spki_hash {
                return true;
            }
        }
    }
    false
}

pub fn verify_trusted_root(chain: &[X509Certificate]) -> Result<(), OnionError> {
    if chain.is_empty() {
        return Err(OnionError::CertificateError);
    }
    let root = &chain[chain.len() - 1];
    // Check the topmost cert's SPKI against our trust store.
    // Do NOT require issuer == subject: the server may send a cross-signed
    // version of the root (e.g. GTS Root R1 cross-signed by GlobalSign)
    // whose issuer differs from its subject but whose key is trusted.
    if is_trusted_root(root) {
        return Ok(());
    }
    // Log the unmatched SPKI hash for debugging (first 8 bytes)
    let hash = sha256(&root.public_key.raw_spki);
    serial::print(b"[CERT] untrusted topmost SPKI(first8): ");
    for &b in hash.iter().take(8) {
        serial::print_hex(b as u64);
        serial::print(b" ");
    }
    serial::println(b"");
    Err(OnionError::CertificateError)
}

pub fn trusted_root_count() -> usize {
    TRUSTED_ROOT_GROUPS.iter().map(|g| g.len()).sum()
}

/// Find all trusted root CAs whose Subject DN matches the given issuer DN.
/// Used for chain building: given a cert's issuer_der, find candidate roots
/// that could have issued it.
pub fn find_roots_by_subject_dn(issuer_der: &[u8]) -> Vec<&'static TrustedRootCa> {
    let mut results = Vec::new();
    for group in TRUSTED_ROOT_GROUPS {
        for root in *group {
            // Skip entries with empty subject_der (incomplete data)
            if !root.subject_der.is_empty() && root.subject_der == issuer_der {
                results.push(root);
            }
        }
    }
    results
}

/// Find all trusted root CAs whose Subject Key Identifier matches the given
/// Authority Key Identifier value. Used to narrow down candidate roots when
/// the child cert has an AKI extension.
pub fn find_roots_by_ski(aki_value: &[u8]) -> Vec<&'static TrustedRootCa> {
    let mut results = Vec::new();
    for group in TRUSTED_ROOT_GROUPS {
        for root in *group {
            if let Some(ski) = root.ski {
                if ski == aki_value {
                    results.push(root);
                }
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    // ISRG Root X1 — known-good DER values from store/isrg.rs
    const ISRG_X1_SUBJECT_DER: &[u8] = &[
        0x30,0x4f,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,
        0x02,0x55,0x53,0x31,0x29,0x30,0x27,0x06,0x03,0x55,0x04,0x0a,
        0x13,0x20,0x49,0x6e,0x74,0x65,0x72,0x6e,0x65,0x74,0x20,0x53,
        0x65,0x63,0x75,0x72,0x69,0x74,0x79,0x20,0x52,0x65,0x73,0x65,
        0x61,0x72,0x63,0x68,0x20,0x47,0x72,0x6f,0x75,0x70,0x31,0x15,
        0x30,0x13,0x06,0x03,0x55,0x04,0x03,0x13,0x0c,0x49,0x53,0x52,
        0x47,0x20,0x52,0x6f,0x6f,0x74,0x20,0x58,0x31,
    ];

    const ISRG_X1_SKI: &[u8] = &[
        0x79,0xb4,0x59,0xe6,0x7b,0xb6,0xe5,0xe4,0x01,0x73,0x80,0x08,
        0x88,0xc8,0x1a,0x58,0xf6,0xe9,0x9b,0x6e,
    ];

    const ISRG_X1_SPKI_SHA256: [u8; 32] = [
        0x0b,0x9f,0xa5,0xa5,0x9e,0xed,0x71,0x5c,
        0x26,0xc1,0x02,0x0c,0x71,0x1b,0x4f,0x6e,
        0xc4,0x2d,0x58,0xb0,0x01,0x5e,0x14,0x33,
        0x7a,0x39,0xda,0xd3,0x01,0xc5,0xaf,0xc3,
    ];

    // ISRG Root X2 — different root, different SKI
    const ISRG_X2_SKI: &[u8] = &[
        0x7c,0x42,0x96,0xae,0xde,0x4b,0x48,0x3b,0xfa,0x92,0xf8,0x9e,
        0x8c,0xcf,0x6d,0x8b,0xa9,0x72,0x37,0x95,
    ];

    #[test]
    fn test_trusted_root_count_is_42() {
        assert_eq!(trusted_root_count(), 42);
    }

    #[test]
    fn test_find_roots_by_subject_dn_isrg_x1() {
        let results = find_roots_by_subject_dn(ISRG_X1_SUBJECT_DER);
        assert!(!results.is_empty(), "ISRG Root X1 should be found by subject DN");
        assert_eq!(results.len(), 1, "exactly one match expected");
        assert_eq!(results[0].name, "ISRG Root X1");
        assert_eq!(results[0].spki_sha256, ISRG_X1_SPKI_SHA256);
    }

    #[test]
    fn test_find_roots_by_subject_dn_no_match() {
        let bogus = &[0xDE, 0xAD, 0xBE, 0xEF];
        let results = find_roots_by_subject_dn(bogus);
        assert!(results.is_empty(), "bogus DN should match nothing");
    }

    #[test]
    fn test_find_roots_by_subject_dn_empty_input() {
        let results = find_roots_by_subject_dn(&[]);
        assert!(results.is_empty(), "empty DN should match nothing");
    }

    #[test]
    fn test_find_roots_by_ski_isrg_x1() {
        let results = find_roots_by_ski(ISRG_X1_SKI);
        assert!(!results.is_empty(), "ISRG Root X1 should be found by SKI");
        assert_eq!(results.len(), 1, "exactly one match expected");
        assert_eq!(results[0].name, "ISRG Root X1");
    }

    #[test]
    fn test_find_roots_by_ski_isrg_x2() {
        let results = find_roots_by_ski(ISRG_X2_SKI);
        assert!(!results.is_empty(), "ISRG Root X2 should be found by SKI");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "ISRG Root X2");
    }

    #[test]
    fn test_find_roots_by_ski_no_match() {
        let bogus = &[0x00, 0x01, 0x02, 0x03];
        let results = find_roots_by_ski(bogus);
        assert!(results.is_empty(), "bogus SKI should match nothing");
    }

    #[test]
    fn test_find_roots_by_ski_empty_input() {
        let results = find_roots_by_ski(&[]);
        assert!(results.is_empty(), "empty SKI should match nothing");
    }

    #[test]
    fn test_trusted_root_ca_has_spki_der() {
        // Every entry with non-empty subject_der should also have non-empty spki_der
        for group in TRUSTED_ROOT_GROUPS {
            for root in *group {
                if !root.subject_der.is_empty() {
                    assert!(
                        !root.spki_der.is_empty(),
                        "CA '{}' has subject_der but empty spki_der",
                        root.name
                    );
                }
            }
        }
    }

    #[test]
    fn test_spki_sha256_matches_spki_der() {
        // For entries with full SPKI DER data, verify the SHA-256 is correct
        use crate::crypto::hash::unified::sha256;
        for group in TRUSTED_ROOT_GROUPS {
            for root in *group {
                if !root.spki_der.is_empty() {
                    let computed = sha256(root.spki_der);
                    assert_eq!(
                        computed, root.spki_sha256,
                        "SPKI SHA-256 mismatch for '{}'",
                        root.name
                    );
                }
            }
        }
    }

    #[test]
    fn test_all_roots_have_names() {
        for group in TRUSTED_ROOT_GROUPS {
            for root in *group {
                assert!(!root.name.is_empty(), "root CA entry should have a name");
            }
        }
    }

    #[test]
    fn test_find_roots_by_dn_and_ski_agree() {
        // For ISRG Root X1, both lookups should find the same root
        let by_dn = find_roots_by_subject_dn(ISRG_X1_SUBJECT_DER);
        let by_ski = find_roots_by_ski(ISRG_X1_SKI);
        assert_eq!(by_dn.len(), 1);
        assert_eq!(by_ski.len(), 1);
        assert_eq!(by_dn[0].name, by_ski[0].name);
        assert_eq!(by_dn[0].spki_sha256, by_ski[0].spki_sha256);
    }
}
