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
use super::super::rsa::RSAPublic;
use super::super::types::{AlgorithmIdentifier, X509Certificate};
use super::super::x509_core::parse_spki_der;
use super::rsa_parse::parse_rsa_public_key;
use super::sig_ed_ecdsa::{verify_ed25519, verify_ecdsa};

pub(crate) fn verify_self_signed(cert: &X509Certificate) -> Result<(), OnionError> {
    verify_signature_internal(cert, &cert.public_key.public_key, &cert.signature_algorithm)
}

pub(crate) fn verify_signature(cert: &X509Certificate, issuer: &X509Certificate) -> Result<(), OnionError> {
    verify_signature_internal(cert, &issuer.public_key.public_key, &cert.signature_algorithm)
}

fn verify_signature_internal(
    cert: &X509Certificate,
    public_key_bytes: &[u8],
    sig_alg: &AlgorithmIdentifier,
) -> Result<(), OnionError> {
    if sig_alg.algorithm.is_rsa_encryption() {
        verify_rsa(cert, public_key_bytes)
    } else if sig_alg.algorithm.is_ed25519() {
        serial::println(b"[X509] sig alg=ed25519");
        verify_ed25519(cert, public_key_bytes)
    } else if sig_alg.algorithm.is_ecdsa() {
        if sig_alg.algorithm.is_ecdsa_sha256() {
            serial::println(b"[X509] sig alg=ecdsa-p256-sha256");
        } else {
            serial::println(b"[X509] sig alg=ecdsa-p384-sha384");
        }
        verify_ecdsa(cert, public_key_bytes, sig_alg.algorithm.is_ecdsa_sha256())
    } else {
        serial::print(b"[X509] unknown sig alg, oid len=");
        serial::print_dec(sig_alg.algorithm.components.len() as u64);
        serial::println(b"");
        if !sig_alg.algorithm.components.is_empty() {
            serial::print(b"[X509] oid: ");
            for c in &sig_alg.algorithm.components {
                serial::print_dec(*c as u64);
                serial::print(b".");
            }
            serial::println(b"");
        }
        Err(OnionError::UnsupportedSignatureAlgorithm)
    }
}

fn verify_rsa(cert: &X509Certificate, public_key_bytes: &[u8]) -> Result<(), OnionError> {
    let public_key = parse_rsa_public_key(public_key_bytes)?;
    let rsa_public = RSAPublic { inner: public_key };

    let ok = if cert.signature_algorithm.algorithm.is_rsa_sha384() {
        serial::println(b"[X509] sig alg=rsa-sha384");
        rsa_public.verify_pkcs1v15_sha384(&cert.tbs_certificate, &cert.signature)
    } else if cert.signature_algorithm.algorithm.is_rsa_sha512() {
        serial::println(b"[X509] sig alg=rsa-sha512");
        rsa_public.verify_pkcs1v15_sha512(&cert.tbs_certificate, &cert.signature)
    } else {
        serial::println(b"[X509] sig alg=rsa-sha256");
        rsa_public.verify_pkcs1v15_sha256(&cert.tbs_certificate, &cert.signature)
    };

    if ok {
        Ok(())
    } else {
        serial::println(b"[X509] RSA verify FAILED");
        Err(OnionError::CertificateSignatureFailed)
    }
}

/// Verify a certificate's signature using a raw SPKI DER blob (from a trusted root CA).
/// Parses the SPKI to extract the algorithm and public key bytes, then dispatches
/// to the appropriate signature verification routine.
pub(crate) fn verify_signature_with_spki_der(
    cert: &X509Certificate,
    spki_der: &[u8],
) -> Result<(), OnionError> {
    let pki = parse_spki_der(spki_der)?;
    // The cert's signature_algorithm specifies the hash (SHA-256, SHA-384, etc.).
    // The SPKI contains the key type. Use both for correct dispatch.
    verify_signature_internal(cert, &pki.public_key, &cert.signature_algorithm)
}
