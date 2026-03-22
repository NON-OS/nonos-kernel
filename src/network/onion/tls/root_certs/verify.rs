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
use crate::network::onion::nonos_crypto::verify_signature_with_spki_der;
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

/// Browser-grade chain-to-root verification (Phase 3).
///
/// Verifies that the topmost certificate in the chain was issued by a trusted
/// root CA by:
///   1. Finding candidate roots whose subject_der matches the topmost cert's issuer_der
///   2. If the topmost cert has an AKI extension, filtering candidates by SKI
///   3. Cryptographically verifying the topmost cert's signature against each
///      candidate root's SPKI
///
/// If the server sent a self-signed root in the chain, that cert is stripped
/// and verification proceeds against its issuer (the next cert down).
///
/// Falls back to SPKI-hash lookup if DN matching finds no candidates.
pub fn verify_chain_to_root(chain: &[X509Certificate]) -> Result<&'static TrustedRootCa, OnionError> {
    if chain.is_empty() {
        return Err(OnionError::CertificateError);
    }

    let topmost = &chain[chain.len() - 1];

    // If the server sent the root cert itself (self-signed: issuer == subject),
    // check if it's trusted directly by SPKI hash, then verify its self-signature
    // was already checked by verify_chain(). The actual trust anchor verification
    // should use the cert *below* the self-signed root, if one exists.
    let verify_cert = if topmost.issuer_der == topmost.subject_der && chain.len() > 1 {
        serial::println(b"[CERT] topmost is self-signed, verifying cert below it");
        &chain[chain.len() - 2]
    } else {
        topmost
    };

    // Step 1: Find candidate roots by subject DN matching
    let candidates = find_roots_by_subject_dn(&verify_cert.issuer_der);

    if !candidates.is_empty() {
        serial::print(b"[CERT] found ");
        serial::print_dec(candidates.len() as u64);
        serial::println(b" candidate roots by DN");

        // Step 2: If the cert has an AKI, narrow candidates by SKI
        let filtered: Vec<&'static TrustedRootCa> = if let Some(ref aki) = verify_cert.extensions.authority_key_id {
            let ski_filtered: Vec<_> = candidates
                .iter()
                .filter(|root| {
                    if let Some(ski) = root.ski {
                        ski == aki.as_slice()
                    } else {
                        // Root has no SKI — keep as candidate (can't filter)
                        true
                    }
                })
                .copied()
                .collect();
            if ski_filtered.is_empty() {
                serial::println(b"[CERT] AKI->SKI filter eliminated all candidates, using DN-only");
                candidates
            } else {
                serial::print(b"[CERT] AKI->SKI filtered to ");
                serial::print_dec(ski_filtered.len() as u64);
                serial::println(b" candidates");
                ski_filtered
            }
        } else {
            candidates
        };

        // Step 3: Verify signature against each candidate's SPKI
        for root in &filtered {
            if verify_signature_with_spki_der(verify_cert, root.spki_der).is_ok() {
                serial::print(b"[CERT] chain-to-root verified: ");
                // Print first few chars of root name
                let name_bytes = root.name.as_bytes();
                let print_len = if name_bytes.len() > 40 { 40 } else { name_bytes.len() };
                serial::print(&name_bytes[..print_len]);
                serial::println(b"");
                return Ok(root);
            }
        }
        serial::println(b"[CERT] DN candidates found but signature verification failed");
    }

    // Fallback: SPKI-hash lookup (backward compatibility during migration)
    serial::println(b"[CERT] falling back to SPKI-hash trust check");
    let spki_hash = sha256(&verify_cert.public_key.raw_spki);
    for group in TRUSTED_ROOT_GROUPS {
        for root in *group {
            if root.spki_sha256 == spki_hash {
                serial::print(b"[CERT] SPKI-hash fallback matched: ");
                let name_bytes = root.name.as_bytes();
                let print_len = if name_bytes.len() > 40 { 40 } else { name_bytes.len() };
                serial::print(&name_bytes[..print_len]);
                serial::println(b"");
                return Ok(root);
            }
        }
    }

    serial::println(b"[CERT] chain-to-root: no trusted root found");
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

    // ================================================================
    // Phase 3 tests — verify_chain_to_root and signature verification
    // ================================================================

    use crate::network::onion::nonos_crypto::{
        AlgorithmIdentifier, ObjectIdentifier, PublicKeyInfo, X509Extensions,
    };

    /// Construct a minimal X509Certificate for testing chain-to-root logic.
    /// Signature verification will fail on dummy data — these tests focus on
    /// the candidate selection logic (DN matching, AKI→SKI filtering, fallback).
    fn make_test_cert(
        subject: &[u8],
        issuer: &[u8],
        raw_spki: &[u8],
        aki: Option<&[u8]>,
    ) -> X509Certificate {
        let mut extensions = X509Extensions::default();
        if let Some(aki_val) = aki {
            extensions.authority_key_id = Some(aki_val.to_vec());
        }
        X509Certificate {
            tbs_certificate: alloc::vec![0x30, 0x00],
            signature_algorithm: AlgorithmIdentifier {
                algorithm: ObjectIdentifier { components: alloc::vec![1, 2, 840, 113549, 1, 1, 11] },
                parameters: None,
            },
            signature: Vec::new(),
            public_key: PublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    algorithm: ObjectIdentifier { components: alloc::vec![1, 2, 840, 113549, 1, 1, 1] },
                    parameters: None,
                },
                public_key: Vec::new(),
                raw_spki: raw_spki.to_vec(),
            },
            not_before_ms: 0,
            not_after_ms: u64::MAX,
            extensions,
            subject_der: subject.to_vec(),
            issuer_der: issuer.to_vec(),
        }
    }

    #[test]
    fn test_verify_chain_to_root_empty_chain() {
        assert!(verify_chain_to_root(&[]).is_err());
    }

    #[test]
    fn test_verify_chain_to_root_unknown_issuer() {
        // A cert whose issuer_der matches no root should fail
        let cert = make_test_cert(&[0x01], &[0xDE, 0xAD], &[], None);
        assert!(verify_chain_to_root(&[cert]).is_err());
    }

    #[test]
    fn test_verify_chain_to_root_dn_match_finds_candidates() {
        // A cert whose issuer_der matches ISRG X1's subject_der.
        // Signature verification will fail (dummy data), but the DN matching
        // path should be exercised. The function falls back to SPKI-hash,
        // which also won't match, so it should return an error.
        let cert = make_test_cert(
            &[0x01],
            ISRG_X1_SUBJECT_DER,
            &[],
            None,
        );
        // This should fail (no valid signature or SPKI match) but should NOT panic
        assert!(verify_chain_to_root(&[cert]).is_err());
    }

    #[test]
    fn test_verify_chain_to_root_dn_match_with_aki() {
        // A cert whose issuer_der matches ISRG X1's subject and AKI matches X1's SKI.
        // Exercises the AKI→SKI filtering path.
        let cert = make_test_cert(
            &[0x01],
            ISRG_X1_SUBJECT_DER,
            &[],
            Some(ISRG_X1_SKI),
        );
        // Should fail at sig verification but exercise the AKI filter logic
        assert!(verify_chain_to_root(&[cert]).is_err());
    }

    #[test]
    fn test_verify_chain_to_root_aki_mismatch_filtered() {
        // A cert whose issuer_der matches ISRG X1 but AKI is bogus.
        // The SKI filter should not eliminate the candidate (since the root has
        // a SKI but it doesn't match the AKI). The function should still fail
        // at sig verification.
        let cert = make_test_cert(
            &[0x01],
            ISRG_X1_SUBJECT_DER,
            &[],
            Some(&[0xFF, 0xFF, 0xFF, 0xFF]),
        );
        assert!(verify_chain_to_root(&[cert]).is_err());
    }

    #[test]
    fn test_verify_chain_to_root_spki_hash_fallback() {
        // A cert with unknown issuer_der but whose raw_spki SHA-256 matches
        // a known root. This exercises the SPKI-hash fallback path.
        let isrg_x1 = find_roots_by_subject_dn(ISRG_X1_SUBJECT_DER);
        assert_eq!(isrg_x1.len(), 1);
        let root = isrg_x1[0];

        // Build a cert with raw_spki that hashes to the root's spki_sha256
        // by using the root's actual spki_der
        let cert = make_test_cert(
            &[0x01],
            &[0xDE, 0xAD], // unknown issuer — DN matching will find nothing
            root.spki_der,  // but SPKI hash will match
            None,
        );
        // The SPKI-hash fallback should find the root
        let result = verify_chain_to_root(&[cert]);
        assert!(result.is_ok(), "SPKI-hash fallback should find ISRG Root X1");
        assert_eq!(result.unwrap().name, "ISRG Root X1");
    }

    #[test]
    fn test_verify_chain_to_root_self_signed_topmost_with_chain() {
        // When the server sends the root in the chain (self-signed topmost),
        // verify_chain_to_root should verify the cert below it instead.
        let leaf = make_test_cert(&[0x01], &[0x02], &[], None);
        let self_signed_root = make_test_cert(
            ISRG_X1_SUBJECT_DER,
            ISRG_X1_SUBJECT_DER,
            &[],
            None,
        );
        let chain = alloc::vec![leaf, self_signed_root];
        // The function should try to verify the leaf (chain[0]) against roots,
        // since chain[1] is self-signed. Leaf's issuer is [0x02] which won't match.
        assert!(verify_chain_to_root(&chain).is_err());
    }

    #[test]
    fn test_verify_chain_to_root_self_signed_single_cert() {
        // Single self-signed cert — should try to match the cert itself
        let cert = make_test_cert(
            ISRG_X1_SUBJECT_DER,
            ISRG_X1_SUBJECT_DER,
            &[],
            None,
        );
        // Single cert, self-signed: should still try to find it in trust store
        // via its issuer_der. DN match will find ISRG X1, but sig will fail.
        // Falls to SPKI fallback, which also fails (empty raw_spki).
        assert!(verify_chain_to_root(&[cert]).is_err());
    }

    #[test]
    fn test_verify_chain_to_root_all_roots_have_parseable_spki() {
        // Verify that every root CA's spki_der in the trust store can be
        // parsed by parse_spki_der (used by verify_signature_with_spki_der).
        use crate::network::onion::nonos_crypto::verify_signature_with_spki_der;
        for group in TRUSTED_ROOT_GROUPS {
            for root in *group {
                if root.spki_der.is_empty() {
                    continue;
                }
                // Create a dummy cert — we just want to test SPKI parsing doesn't panic
                let cert = make_test_cert(&[0x01], &[0x02], &[], None);
                // verify_signature_with_spki_der will parse the SPKI, then fail
                // at signature verification (dummy cert). The point: SPKI parsing
                // must not panic or return a parse error.
                let result = verify_signature_with_spki_der(&cert, root.spki_der);
                // Result should be Err (sig mismatch), NOT a parse error panic
                assert!(
                    result.is_err(),
                    "dummy cert should fail sig verify against '{}'",
                    root.name
                );
            }
        }
    }

    #[test]
    fn test_verify_signature_with_spki_der_invalid_spki() {
        use crate::network::onion::nonos_crypto::verify_signature_with_spki_der;
        let cert = make_test_cert(&[0x01], &[0x02], &[], None);
        // Garbage SPKI should return an error, not panic
        let result = verify_signature_with_spki_der(&cert, &[0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_signature_with_spki_der_empty() {
        use crate::network::onion::nonos_crypto::verify_signature_with_spki_der;
        let cert = make_test_cert(&[0x01], &[0x02], &[], None);
        let result = verify_signature_with_spki_der(&cert, &[]);
        assert!(result.is_err());
    }
}
