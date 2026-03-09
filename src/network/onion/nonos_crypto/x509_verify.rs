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
    if sig_alg.algorithm.is_rsa_encryption() {
        let public_key = parse_rsa_public_key(public_key_bytes)?;
        let rsa_public = RSAPublic { inner: public_key };

        if rsa_public.verify_pkcs1v15_sha256(&cert.tbs_certificate, &cert.signature) {
            Ok(())
        } else {
            Err(OnionError::CryptoError)
        }
    } else if sig_alg.algorithm.is_ed25519() {
        if public_key_bytes.len() != 32 || cert.signature.len() != 64 {
            return Err(OnionError::CryptoError);
        }

        let mut public_key = [0u8; 32];
        let mut signature = [0u8; 64];
        public_key.copy_from_slice(public_key_bytes);
        signature.copy_from_slice(&cert.signature);

        if RealEd25519::verify(&cert.tbs_certificate, &signature, &public_key) {
            Ok(())
        } else {
            Err(OnionError::CryptoError)
        }
    } else if sig_alg.algorithm.is_ecdsa_sha256() {
        if super::ecdsa_p256_sha256_verify_spki(public_key_bytes, &cert.tbs_certificate, &cert.signature)? {
            Ok(())
        } else {
            Err(OnionError::CryptoError)
        }
    } else {
        Err(OnionError::CryptoError)
    }
}

fn parse_rsa_public_key(key_bytes: &[u8]) -> Result<rsa::RsaPublicKey, OnionError> {
    let mut parser = DerParser::new(key_bytes);
    parser.expect_sequence()?;

    parser.expect_tag(0x02)?;
    let n_len = parser.read_length()?;
    let n = parser.read_bytes(n_len)?.to_vec();

    parser.expect_tag(0x02)?;
    let e_len = parser.read_length()?;
    let e = parser.read_bytes(e_len)?.to_vec();

    Ok(rsa::create_public_key(n, e))
}

pub(crate) fn verify_chain(chain: &[X509Certificate], now_ms: u64) -> Result<(), OnionError> {
    if chain.is_empty() {
        return Err(OnionError::CertificateError);
    }

    for cert in chain.iter() {
        check_time_validity(cert, now_ms)?;
    }

    for i in 0..chain.len() - 1 {
        let cert = &chain[i];
        let issuer = &chain[i + 1];

        if cert.issuer_der != issuer.subject_der {
            return Err(OnionError::CertificateError);
        }

        verify_signature(cert, issuer)?;
    }

    Ok(())
}

pub(crate) fn check_basic_constraints_end_entity(cert: &X509Certificate) -> Result<(), OnionError> {
    if cert.is_ca {
        return Err(OnionError::CertificateError);
    }
    Ok(())
}
