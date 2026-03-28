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
use crate::sys::serial;
use super::super::types::{X509Certificate, ExtKeyUsage, KU_KEY_CERT_SIGN, KU_KEY_ENCIPHERMENT, KU_DIGITAL_SIGNATURE};

pub(crate) fn check_basic_constraints_end_entity(cert: &X509Certificate) -> Result<(), OnionError> {
    if cert.extensions.basic_constraints.ca {
        return Err(OnionError::CertificateError);
    }
    Ok(())
}

/// Verify that a CA certificate (non-leaf, non-root) has the required constraints:
/// - Basic Constraints: ca must be true (RFC 5280 §4.2.1.9)
/// - Key Usage: if present, must include keyCertSign (RFC 5280 §4.2.1.3)
pub(crate) fn check_ca_constraints(cert: &X509Certificate, cert_index: usize) -> Result<(), OnionError> {
    if !cert.extensions.basic_constraints.ca {
        serial::print(b"[X509] cert ");
        serial::print_dec(cert_index as u64);
        serial::println(b" is intermediate but BasicConstraints.ca=false");
        return Err(OnionError::CertificateError);
    }
    // Key Usage check: if KU extension is present (non-zero), keyCertSign must be set
    if cert.extensions.key_usage != 0 && (cert.extensions.key_usage & KU_KEY_CERT_SIGN) == 0 {
        serial::print(b"[X509] cert ");
        serial::print_dec(cert_index as u64);
        serial::println(b" is CA but missing keyCertSign in KeyUsage");
        return Err(OnionError::CertificateError);
    }
    Ok(())
}

/// Enforce pathLenConstraint across the certificate chain.
/// For each CA cert with a pathLenConstraint, the number of CA certs below it
/// (between it and the leaf) must not exceed the constraint value.
/// RFC 5280 §4.2.1.9: pathLenConstraint gives the maximum number of
/// non-self-issued intermediate certificates that may follow this certificate
/// in a valid certification path.
pub(crate) fn check_path_len_constraints(chain: &[X509Certificate]) -> Result<(), OnionError> {
    // chain[0] = leaf, chain[1..n-1] = intermediates, chain[n-1] = topmost
    // For each intermediate/root cert at index i, if it has pathLenConstraint,
    // the number of CA certs between it (exclusive) and the leaf (exclusive)
    // must not exceed the constraint.
    for i in 1..chain.len() {
        if let Some(max_path) = chain[i].extensions.basic_constraints.path_len_constraint {
            // Count CA certs below this one (between index i and the leaf at 0)
            // Those are chain[1..i] — the intermediates below this cert
            let ca_certs_below = (i - 1) as u8;
            if ca_certs_below > max_path {
                serial::print(b"[X509] pathLenConstraint violated at cert ");
                serial::print_dec(i as u64);
                serial::print(b": ");
                serial::print_dec(ca_certs_below as u64);
                serial::print(b" CAs below, max ");
                serial::print_dec(max_path as u64);
                serial::println(b"");
                return Err(OnionError::CertificateError);
            }
        }
    }
    Ok(())
}

/// Check EKU on the leaf certificate for HTTPS connections.
/// RFC 5280 §4.2.1.12: if EKU extension is present, it must contain ServerAuth.
/// If the extension is absent, the certificate is allowed (no restriction).
pub(crate) fn check_eku_server_auth(cert: &X509Certificate) -> Result<(), OnionError> {
    if cert.extensions.ext_key_usage.is_empty() {
        // EKU absent — allowed per RFC 5280
        return Ok(());
    }
    if cert.extensions.ext_key_usage.contains(&ExtKeyUsage::ServerAuth) {
        return Ok(());
    }
    serial::println(b"[X509] leaf cert EKU present but missing ServerAuth");
    Err(OnionError::CertificateError)
}

/// Check Key Usage on the leaf certificate.
/// RFC 5280 §4.2.1.3: if KU extension is present, digitalSignature should be set
/// for TLS leaf certs. Also accept keyEncipherment for RSA key transport certs
/// (browsers accept both). If KU is absent (zero), allow.
pub(crate) fn check_leaf_key_usage(cert: &X509Certificate) -> Result<(), OnionError> {
    if cert.extensions.key_usage == 0 {
        // KU absent — allowed per RFC 5280
        return Ok(());
    }
    if (cert.extensions.key_usage & (KU_DIGITAL_SIGNATURE | KU_KEY_ENCIPHERMENT)) != 0 {
        return Ok(());
    }
    serial::println(b"[X509] leaf cert KU present but missing digitalSignature/keyEncipherment");
    Err(OnionError::CertificateError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::types::{
        AlgorithmIdentifier, ObjectIdentifier, PublicKeyInfo, X509Extensions,
        BasicConstraints,
    };
    use alloc::vec;
    use alloc::vec::Vec;

    fn make_cert_with_ext(extensions: X509Extensions) -> X509Certificate {
        X509Certificate {
            tbs_certificate: vec![0x30, 0x00],
            signature_algorithm: AlgorithmIdentifier {
                algorithm: ObjectIdentifier { components: vec![1, 2, 840, 113549, 1, 1, 11] },
                parameters: None,
            },
            signature: Vec::new(),
            public_key: PublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    algorithm: ObjectIdentifier { components: vec![1, 2, 840, 113549, 1, 1, 1] },
                    parameters: None,
                },
                public_key: Vec::new(),
                raw_spki: Vec::new(),
            },
            not_before_ms: 0,
            not_after_ms: u64::MAX,
            extensions,
            subject_der: vec![0x01],
            issuer_der: vec![0x02],
        }
    }

    // --- check_basic_constraints_end_entity ---

    #[test]
    fn test_end_entity_non_ca_ok() {
        let cert = make_cert_with_ext(X509Extensions::default());
        assert!(check_basic_constraints_end_entity(&cert).is_ok());
    }

    #[test]
    fn test_end_entity_ca_rejected() {
        let mut ext = X509Extensions::default();
        ext.basic_constraints = BasicConstraints { ca: true, path_len_constraint: None };
        let cert = make_cert_with_ext(ext);
        assert!(check_basic_constraints_end_entity(&cert).is_err());
    }

    // --- check_ca_constraints ---

    #[test]
    fn test_ca_with_bc_true_ok() {
        let mut ext = X509Extensions::default();
        ext.basic_constraints = BasicConstraints { ca: true, path_len_constraint: None };
        let cert = make_cert_with_ext(ext);
        assert!(check_ca_constraints(&cert, 1).is_ok());
    }

    #[test]
    fn test_ca_with_bc_false_rejected() {
        let cert = make_cert_with_ext(X509Extensions::default());
        assert!(check_ca_constraints(&cert, 1).is_err());
    }

    #[test]
    fn test_ca_with_ku_cert_sign_ok() {
        let mut ext = X509Extensions::default();
        ext.basic_constraints = BasicConstraints { ca: true, path_len_constraint: None };
        ext.key_usage = KU_KEY_CERT_SIGN;
        let cert = make_cert_with_ext(ext);
        assert!(check_ca_constraints(&cert, 1).is_ok());
    }

    #[test]
    fn test_ca_with_ku_no_cert_sign_rejected() {
        let mut ext = X509Extensions::default();
        ext.basic_constraints = BasicConstraints { ca: true, path_len_constraint: None };
        ext.key_usage = KU_DIGITAL_SIGNATURE; // present but missing keyCertSign
        let cert = make_cert_with_ext(ext);
        assert!(check_ca_constraints(&cert, 1).is_err());
    }

    #[test]
    fn test_ca_with_ku_absent_ok() {
        let mut ext = X509Extensions::default();
        ext.basic_constraints = BasicConstraints { ca: true, path_len_constraint: None };
        ext.key_usage = 0; // absent
        let cert = make_cert_with_ext(ext);
        assert!(check_ca_constraints(&cert, 1).is_ok());
    }

    // --- check_path_len_constraints ---

    #[test]
    fn test_pathlen_zero_with_no_intermediates() {
        // chain: [leaf, CA(pathLen=0)]
        let leaf = make_cert_with_ext(X509Extensions::default());
        let mut ca_ext = X509Extensions::default();
        ca_ext.basic_constraints = BasicConstraints { ca: true, path_len_constraint: Some(0) };
        let ca = make_cert_with_ext(ca_ext);
        assert!(check_path_len_constraints(&[leaf, ca]).is_ok());
    }

    #[test]
    fn test_pathlen_zero_with_one_intermediate_rejected() {
        // chain: [leaf, intermediate, CA(pathLen=0)]
        // CA allows 0 CAs below it, but there's 1 intermediate → reject
        let leaf = make_cert_with_ext(X509Extensions::default());
        let mut int_ext = X509Extensions::default();
        int_ext.basic_constraints = BasicConstraints { ca: true, path_len_constraint: None };
        let intermediate = make_cert_with_ext(int_ext);
        let mut ca_ext = X509Extensions::default();
        ca_ext.basic_constraints = BasicConstraints { ca: true, path_len_constraint: Some(0) };
        let ca = make_cert_with_ext(ca_ext);
        assert!(check_path_len_constraints(&[leaf, intermediate, ca]).is_err());
    }

    #[test]
    fn test_pathlen_one_with_one_intermediate_ok() {
        let leaf = make_cert_with_ext(X509Extensions::default());
        let mut int_ext = X509Extensions::default();
        int_ext.basic_constraints = BasicConstraints { ca: true, path_len_constraint: None };
        let intermediate = make_cert_with_ext(int_ext);
        let mut ca_ext = X509Extensions::default();
        ca_ext.basic_constraints = BasicConstraints { ca: true, path_len_constraint: Some(1) };
        let ca = make_cert_with_ext(ca_ext);
        assert!(check_path_len_constraints(&[leaf, intermediate, ca]).is_ok());
    }

    #[test]
    fn test_pathlen_none_allows_any_depth() {
        let leaf = make_cert_with_ext(X509Extensions::default());
        let mut int_ext1 = X509Extensions::default();
        int_ext1.basic_constraints = BasicConstraints { ca: true, path_len_constraint: None };
        let int1 = make_cert_with_ext(int_ext1);
        let mut int_ext2 = X509Extensions::default();
        int_ext2.basic_constraints = BasicConstraints { ca: true, path_len_constraint: None };
        let int2 = make_cert_with_ext(int_ext2);
        let mut ca_ext = X509Extensions::default();
        ca_ext.basic_constraints = BasicConstraints { ca: true, path_len_constraint: None };
        let ca = make_cert_with_ext(ca_ext);
        assert!(check_path_len_constraints(&[leaf, int1, int2, ca]).is_ok());
    }

    // --- check_eku_server_auth ---

    #[test]
    fn test_eku_absent_allowed() {
        let cert = make_cert_with_ext(X509Extensions::default());
        assert!(check_eku_server_auth(&cert).is_ok());
    }

    #[test]
    fn test_eku_server_auth_present_ok() {
        let mut ext = X509Extensions::default();
        ext.ext_key_usage = vec![ExtKeyUsage::ServerAuth];
        let cert = make_cert_with_ext(ext);
        assert!(check_eku_server_auth(&cert).is_ok());
    }

    #[test]
    fn test_eku_server_and_client_ok() {
        let mut ext = X509Extensions::default();
        ext.ext_key_usage = vec![ExtKeyUsage::ServerAuth, ExtKeyUsage::ClientAuth];
        let cert = make_cert_with_ext(ext);
        assert!(check_eku_server_auth(&cert).is_ok());
    }

    #[test]
    fn test_eku_client_only_rejected() {
        let mut ext = X509Extensions::default();
        ext.ext_key_usage = vec![ExtKeyUsage::ClientAuth];
        let cert = make_cert_with_ext(ext);
        assert!(check_eku_server_auth(&cert).is_err());
    }

    #[test]
    fn test_eku_ocsp_only_rejected() {
        let mut ext = X509Extensions::default();
        ext.ext_key_usage = vec![ExtKeyUsage::OcspSigning];
        let cert = make_cert_with_ext(ext);
        assert!(check_eku_server_auth(&cert).is_err());
    }

    // --- check_leaf_key_usage ---

    #[test]
    fn test_leaf_ku_absent_allowed() {
        let cert = make_cert_with_ext(X509Extensions::default());
        assert!(check_leaf_key_usage(&cert).is_ok());
    }

    #[test]
    fn test_leaf_ku_digital_signature_ok() {
        let mut ext = X509Extensions::default();
        ext.key_usage = KU_DIGITAL_SIGNATURE;
        let cert = make_cert_with_ext(ext);
        assert!(check_leaf_key_usage(&cert).is_ok());
    }

    #[test]
    fn test_leaf_ku_cert_sign_only_rejected() {
        let mut ext = X509Extensions::default();
        ext.key_usage = KU_KEY_CERT_SIGN; // CA-only usage, no digitalSignature
        let cert = make_cert_with_ext(ext);
        assert!(check_leaf_key_usage(&cert).is_err());
    }

    #[test]
    fn test_leaf_ku_digital_sig_and_more_ok() {
        let mut ext = X509Extensions::default();
        ext.key_usage = KU_DIGITAL_SIGNATURE | KU_KEY_ENCIPHERMENT;
        let cert = make_cert_with_ext(ext);
        assert!(check_leaf_key_usage(&cert).is_ok());
    }

    #[test]
    fn test_leaf_ku_key_encipherment_only_ok() {
        // RSA key transport certs may only have keyEncipherment — browsers accept this
        let mut ext = X509Extensions::default();
        ext.key_usage = KU_KEY_ENCIPHERMENT;
        let cert = make_cert_with_ext(ext);
        assert!(check_leaf_key_usage(&cert).is_ok());
    }

    #[test]
    fn test_leaf_ku_crl_sign_only_rejected() {
        // cRLSign alone is not valid for a TLS leaf cert
        let mut ext = X509Extensions::default();
        ext.key_usage = KU_CRL_SIGN;
        let cert = make_cert_with_ext(ext);
        assert!(check_leaf_key_usage(&cert).is_err());
    }
}
