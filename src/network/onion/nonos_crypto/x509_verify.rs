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

use crate::crypto::rsa;
use crate::network::onion::OnionError;
use super::curve::RealEd25519;
use super::rsa::RSAPublic;
use super::types::X509Certificate;
use super::x509_der::DerParser;
use super::x509_time::check_time_validity;

pub(crate) fn verify_self_signed(cert: &X509Certificate) -> Result<(), OnionError> {
    verify_signature_internal(cert, &cert.public_key.public_key, &cert.signature_algorithm)
}

pub(crate) fn verify_signature(cert: &X509Certificate, issuer: &X509Certificate) -> Result<(), OnionError> {
    verify_signature_internal(cert, &issuer.public_key.public_key, &cert.signature_algorithm)
}

fn verify_signature_internal(
    cert: &X509Certificate,
    public_key_bytes: &[u8],
    sig_alg: &super::types::AlgorithmIdentifier,
) -> Result<(), OnionError> {
    use crate::sys::serial;

    serial::print(b"[X509] verify_sig: pk_len=");
    serial::print_dec(public_key_bytes.len() as u64);
    serial::print(b" sig_len=");
    serial::print_dec(cert.signature.len() as u64);
    serial::print(b" tbs_len=");
    serial::print_dec(cert.tbs_certificate.len() as u64);
    serial::println(b"");

    if sig_alg.algorithm.is_rsa_encryption() {
        serial::println(b"[X509] using RSA verification");
        let public_key = parse_rsa_public_key(public_key_bytes)?;
        let rsa_public = RSAPublic { inner: public_key };

        if rsa_public.verify_pkcs1v15_sha256(&cert.tbs_certificate, &cert.signature) {
            serial::println(b"[X509] RSA verify OK");
            Ok(())
        } else {
            serial::println(b"[X509] RSA verify FAILED");
            Err(OnionError::CryptoError)
        }
    } else if sig_alg.algorithm.is_ed25519() {
        serial::println(b"[X509] using Ed25519 verification");
        if public_key_bytes.len() != 32 || cert.signature.len() != 64 {
            serial::println(b"[X509] Ed25519 wrong lengths");
            return Err(OnionError::CryptoError);
        }

        let mut public_key = [0u8; 32];
        let mut signature = [0u8; 64];
        public_key.copy_from_slice(public_key_bytes);
        signature.copy_from_slice(&cert.signature);

        if RealEd25519::verify(&cert.tbs_certificate, &signature, &public_key) {
            serial::println(b"[X509] Ed25519 verify OK");
            Ok(())
        } else {
            serial::println(b"[X509] Ed25519 verify FAILED");
            Err(OnionError::CryptoError)
        }
    } else if sig_alg.algorithm.is_ecdsa() {
        serial::println(b"[X509] using ECDSA verification");
        match super::ecdsa_p256_sha256_verify_spki(public_key_bytes, &cert.tbs_certificate, &cert.signature) {
            Ok(true) => {
                serial::println(b"[X509] ECDSA verify OK");
                Ok(())
            }
            Ok(false) => {
                serial::println(b"[X509] ECDSA verify FAILED");
                Err(OnionError::CryptoError)
            }
            Err(e) => {
                serial::println(b"[X509] ECDSA verify ERROR");
                Err(e)
            }
        }
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
        Err(OnionError::CryptoError)
    }
}

fn parse_rsa_public_key(key_bytes: &[u8]) -> Result<rsa::RsaPublicKey, OnionError> {
    let mut parser = DerParser::new(key_bytes);
    parser.expect_sequence()?;
    let _seq_len = parser.read_length()?;

    parser.expect_tag(0x02)?;
    let n_len = parser.read_length()?;
    let n = parser.read_bytes(n_len)?.to_vec();

    parser.expect_tag(0x02)?;
    let e_len = parser.read_length()?;
    let e = parser.read_bytes(e_len)?.to_vec();

    Ok(rsa::create_public_key(n, e))
}

pub(crate) fn verify_chain(chain: &[X509Certificate], now_ms: u64) -> Result<(), OnionError> {
    use crate::sys::serial;

    if chain.is_empty() {
        serial::println(b"[X509] verify_chain: empty chain");
        return Err(OnionError::CertificateError);
    }

    serial::print(b"[X509] verify_chain: ");
    serial::print_dec(chain.len() as u64);
    serial::println(b" certs");

    for (idx, cert) in chain.iter().enumerate() {
        if let Err(e) = check_time_validity(cert, now_ms) {
            serial::print(b"[X509] cert ");
            serial::print_dec(idx as u64);
            serial::println(b" time validity failed");
            return Err(e);
        }
    }

    for i in 0..chain.len() - 1 {
        let cert = &chain[i];
        let issuer = &chain[i + 1];

        serial::print(b"[X509] checking cert ");
        serial::print_dec(i as u64);
        serial::print(b" -> issuer ");
        serial::print_dec((i + 1) as u64);
        serial::println(b"");

        if cert.issuer_der != issuer.subject_der {
            serial::println(b"[X509] ERROR: issuer/subject mismatch");
            serial::print(b"[X509] cert issuer len=");
            serial::print_dec(cert.issuer_der.len() as u64);
            serial::print(b" subject len=");
            serial::print_dec(issuer.subject_der.len() as u64);
            serial::println(b"");
            return Err(OnionError::CertificateError);
        }
        serial::println(b"[X509] issuer/subject match OK");

        if let Err(e) = verify_signature(cert, issuer) {
            serial::println(b"[X509] ERROR: signature verify failed");
            serial::print(b"[X509] sig_alg oid len=");
            serial::print_dec(cert.signature_algorithm.algorithm.components.len() as u64);
            serial::println(b"");
            return Err(e);
        }
        serial::println(b"[X509] signature OK");
    }

    let root = &chain[chain.len() - 1];
    if root.issuer_der == root.subject_der {
        serial::println(b"[X509] verifying self-signed root");
        if let Err(e) = verify_self_signed(root) {
            serial::println(b"[X509] ERROR: root self-sign failed");
            return Err(e);
        }
        serial::println(b"[X509] root self-sign OK");
    }

    serial::println(b"[X509] verify_chain: SUCCESS");
    Ok(())
}

pub(crate) fn check_basic_constraints_end_entity(cert: &X509Certificate) -> Result<(), OnionError> {
    if cert.is_ca {
        return Err(OnionError::CertificateError);
    }
    Ok(())
}
