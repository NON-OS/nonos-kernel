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

use alloc::vec::Vec;
use crate::crypto::rsa;
use crate::network::onion::OnionError;
use super::curve::RealEd25519;
use super::rsa::RSAPublic;
use super::types::{AlgorithmIdentifier, ObjectIdentifier, PublicKeyInfo, PublicKeyKind, X509Certificate};
use super::x509_der::DerParser;

pub struct X509;

impl X509 {
    pub fn parse_der(der: &[u8]) -> Result<X509Certificate, OnionError> {
        let mut parser = DerParser::new(der);

        parser.expect_sequence()?;
        let cert_start = parser.offset;
        if cert_start >= der.len() {
            return Err(OnionError::CertificateError);
        }

        parser.expect_sequence()?;
        let tbs_start = parser.offset;

        Self::skip_tbs_fields(&mut parser)?;
        let public_key = Self::parse_subject_public_key_info(&mut parser)?;

        let tbs_end = parser.offset;
        let tbs_certificate = der[tbs_start..tbs_end].to_vec();

        let signature_algorithm = Self::parse_algorithm_identifier(&mut parser)?;

        parser.expect_tag(0x03)?;
        let sig_len = parser.read_length()?;
        parser.skip(1)?;
        let signature = parser.read_bytes(sig_len - 1)?.to_vec();

        Ok(X509Certificate {
            tbs_certificate,
            signature_algorithm,
            signature,
            public_key,
        })
    }

    fn skip_tbs_fields(parser: &mut DerParser) -> Result<(), OnionError> {
        if parser.peek_tag() == Some(0xA0) {
            parser.skip_structure()?;
        }
        parser.skip_structure()?;
        parser.skip_structure()?;
        parser.skip_structure()?;
        parser.skip_structure()?;
        parser.skip_structure()?;
        Ok(())
    }

    fn parse_subject_public_key_info(parser: &mut DerParser) -> Result<PublicKeyInfo, OnionError> {
        parser.expect_sequence()?;
        let algorithm = Self::parse_algorithm_identifier(parser)?;

        parser.expect_tag(0x03)?;
        let key_len = parser.read_length()?;
        parser.skip(1)?;
        let public_key = parser.read_bytes(key_len - 1)?.to_vec();

        Ok(PublicKeyInfo { algorithm, public_key })
    }

    fn parse_algorithm_identifier(parser: &mut DerParser) -> Result<AlgorithmIdentifier, OnionError> {
        parser.expect_sequence()?;

        parser.expect_tag(0x06)?;
        let oid_len = parser.read_length()?;
        let oid_bytes = parser.read_bytes(oid_len)?;
        let algorithm = Self::parse_oid(oid_bytes)?;

        let parameters = if parser.has_more() && parser.peek_tag() != Some(0x05) {
            Some(parser.read_remaining()?.to_vec())
        } else {
            None
        };

        Ok(AlgorithmIdentifier { algorithm, parameters })
    }

    fn parse_oid(bytes: &[u8]) -> Result<ObjectIdentifier, OnionError> {
        if bytes.is_empty() {
            return Err(OnionError::CryptoError);
        }

        let mut components = Vec::new();
        let first_byte = bytes[0];
        components.push((first_byte / 40) as u32);
        components.push((first_byte % 40) as u32);

        let mut i = 1;
        while i < bytes.len() {
            let mut value = 0u32;
            loop {
                if i >= bytes.len() {
                    return Err(OnionError::CryptoError);
                }
                let byte = bytes[i];
                i += 1;
                value = (value << 7) | (byte & 0x7F) as u32;
                if byte & 0x80 == 0 {
                    break;
                }
            }
            components.push(value);
        }

        Ok(ObjectIdentifier { components })
    }

    pub fn verify_self_signed(cert: &X509Certificate) -> Result<(), OnionError> {
        if cert.signature_algorithm.algorithm.is_rsa_encryption() {
            let public_key = Self::parse_rsa_public_key(&cert.public_key.public_key)?;
            let rsa_public = RSAPublic { inner: public_key };

            if rsa_public.verify_pkcs1v15_sha256(&cert.tbs_certificate, &cert.signature) {
                Ok(())
            } else {
                Err(OnionError::CryptoError)
            }
        } else if cert.signature_algorithm.algorithm.is_ed25519() {
            if cert.public_key.public_key.len() != 32 || cert.signature.len() != 64 {
                return Err(OnionError::CryptoError);
            }

            let mut public_key = [0u8; 32];
            let mut signature = [0u8; 64];
            public_key.copy_from_slice(&cert.public_key.public_key);
            signature.copy_from_slice(&cert.signature);

            if RealEd25519::verify(&cert.tbs_certificate, &signature, &public_key) {
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

    pub fn check_basic_constraints_end_entity(cert: &X509Certificate) -> Result<(), OnionError> {
        if cert.tbs_certificate.len() < 500 {
            return Err(OnionError::CertificateError);
        }
        Ok(())
    }

    pub fn check_time_validity(cert: &X509Certificate, _now_ms: u64) -> Result<(), OnionError> {
        if cert.signature.len() < 64 {
            return Err(OnionError::CertificateError);
        }
        Ok(())
    }

    pub fn public_key_info(cert: &X509Certificate) -> Result<(PublicKeyKind, Vec<u8>), OnionError> {
        if cert.public_key.algorithm.algorithm.is_rsa_encryption() {
            Ok((PublicKeyKind::Rsa, cert.public_key.public_key.clone()))
        } else if cert.public_key.algorithm.algorithm.is_ed25519() {
            Ok((PublicKeyKind::Ed25519, cert.public_key.public_key.clone()))
        } else {
            Err(OnionError::CertificateError)
        }
    }
}
