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
use crate::network::onion::OnionError;
use super::types::{AlgorithmIdentifier, ObjectIdentifier, PublicKeyInfo, PublicKeyKind, X509Certificate};
use super::x509_der::DerParser;
use super::x509_time::parse_validity;
use super::x509_verify::{
    verify_self_signed, verify_signature, verify_chain,
    check_basic_constraints_end_entity,
};
pub(crate) use super::x509_time::check_time_validity;

pub struct X509;

impl X509 {
    pub fn parse_der(der: &[u8]) -> Result<X509Certificate, OnionError> {
        crate::sys::serial::print(b"[X509] parse_der len=");
        crate::sys::serial::print_dec(der.len() as u64);
        crate::sys::serial::println(b"");

        let mut parser = DerParser::new(der);

        crate::sys::serial::println(b"[X509] expect outer sequence");
        parser.expect_sequence()?;
        let _outer_len = parser.read_length()?;
        let cert_start = parser.offset;
        if cert_start >= der.len() {
            crate::sys::serial::println(b"[X509] ERROR: cert_start >= len");
            return Err(OnionError::CertificateError);
        }

        crate::sys::serial::println(b"[X509] expect tbs sequence");
        let tbs_start = parser.offset;
        parser.expect_sequence()?;
        let tbs_len = parser.read_length()?;
        let tbs_content_end = parser.offset + tbs_len;

        crate::sys::serial::println(b"[X509] parse_tbs_fields");
        let (not_before_ms, not_after_ms, issuer_der, subject_der, is_ca) = Self::parse_tbs_fields(&mut parser)?;

        crate::sys::serial::println(b"[X509] parse_subject_public_key_info");
        let public_key = Self::parse_subject_public_key_info(&mut parser)?;

        crate::sys::serial::println(b"[X509] skip_extensions");
        Self::skip_extensions(&mut parser)?;

        parser.offset = tbs_content_end;
        let tbs_certificate = der[tbs_start..tbs_content_end].to_vec();

        crate::sys::serial::println(b"[X509] parse sig_algorithm");
        let signature_algorithm = Self::parse_algorithm_identifier(&mut parser)?;

        crate::sys::serial::println(b"[X509] reading signature");
        parser.expect_tag(0x03)?;
        let sig_len = parser.read_length()?;
        parser.skip(1)?;
        let signature = parser.read_bytes(sig_len - 1)?.to_vec();

        crate::sys::serial::println(b"[X509] parse OK");
        Ok(X509Certificate {
            tbs_certificate,
            signature_algorithm,
            signature,
            public_key,
            not_before_ms,
            not_after_ms,
            is_ca,
            subject_der,
            issuer_der,
        })
    }

    fn parse_tbs_fields(parser: &mut DerParser) -> Result<(u64, u64, Vec<u8>, Vec<u8>, bool), OnionError> {
        crate::sys::serial::print(b"[X509] tbs offset=");
        crate::sys::serial::print_dec(parser.offset as u64);
        crate::sys::serial::print(b" tag=0x");
        if let Some(t) = parser.peek_tag() {
            crate::sys::serial::print_hex(t as u64);
        }
        crate::sys::serial::println(b"");

        if parser.peek_tag() == Some(0xA0) {
            crate::sys::serial::println(b"[X509] skipping version");
            parser.skip_structure()?;
        }
        crate::sys::serial::println(b"[X509] skipping serialNumber");
        parser.skip_structure()?;
        crate::sys::serial::println(b"[X509] skipping signature");
        parser.skip_structure()?;

        crate::sys::serial::println(b"[X509] reading issuer");
        let issuer_start = parser.offset;
        parser.skip_structure()?;
        let issuer_end = parser.offset;
        let issuer_der = parser.data[issuer_start..issuer_end].to_vec();

        crate::sys::serial::println(b"[X509] parsing validity");
        let (not_before_ms, not_after_ms) = parse_validity(parser)?;

        crate::sys::serial::println(b"[X509] reading subject");
        let subject_start = parser.offset;
        parser.skip_structure()?;
        let subject_end = parser.offset;
        let subject_der = parser.data[subject_start..subject_end].to_vec();

        crate::sys::serial::println(b"[X509] tbs_fields done");
        Ok((not_before_ms, not_after_ms, issuer_der, subject_der, false))
    }

    fn skip_extensions(parser: &mut DerParser) -> Result<(), OnionError> {
        while parser.has_more() && parser.peek_tag() == Some(0xA3) {
            parser.skip_structure()?;
        }
        Ok(())
    }

    fn parse_subject_public_key_info(parser: &mut DerParser) -> Result<PublicKeyInfo, OnionError> {
        parser.expect_sequence()?;
        let spki_len = parser.read_length()?;
        let spki_end = parser.offset + spki_len;
        let algorithm = Self::parse_algorithm_identifier(parser)?;

        parser.expect_tag(0x03)?;
        let key_len = parser.read_length()?;
        parser.skip(1)?;
        let public_key = parser.read_bytes(key_len - 1)?.to_vec();

        parser.offset = spki_end;
        Ok(PublicKeyInfo { algorithm, public_key })
    }

    fn parse_algorithm_identifier(parser: &mut DerParser) -> Result<AlgorithmIdentifier, OnionError> {
        parser.expect_sequence()?;
        let alg_len = parser.read_length()?;
        let alg_end = parser.offset + alg_len;

        parser.expect_tag(0x06)?;
        let oid_len = parser.read_length()?;
        let oid_bytes = parser.read_bytes(oid_len)?;
        let algorithm = Self::parse_oid(oid_bytes)?;

        let parameters = if parser.offset < alg_end {
            let remaining = alg_end - parser.offset;
            Some(parser.read_bytes(remaining)?.to_vec())
        } else {
            None
        };

        parser.offset = alg_end;
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
        verify_self_signed(cert)
    }

    pub fn verify_signature(cert: &X509Certificate, issuer: &X509Certificate) -> Result<(), OnionError> {
        verify_signature(cert, issuer)
    }

    pub fn verify_chain(chain: &[X509Certificate], now_ms: u64) -> Result<(), OnionError> {
        verify_chain(chain, now_ms)
    }

    pub fn check_basic_constraints_end_entity(cert: &X509Certificate) -> Result<(), OnionError> {
        check_basic_constraints_end_entity(cert)
    }

    pub fn check_time_validity(cert: &X509Certificate, now_ms: u64) -> Result<(), OnionError> {
        check_time_validity(cert, now_ms)
    }

    pub fn public_key_info(cert: &X509Certificate) -> Result<(PublicKeyKind, Vec<u8>), OnionError> {
        if cert.public_key.algorithm.algorithm.is_rsa_encryption() {
            Ok((PublicKeyKind::Rsa, cert.public_key.public_key.clone()))
        } else if cert.public_key.algorithm.algorithm.is_ed25519() {
            Ok((PublicKeyKind::Ed25519, cert.public_key.public_key.clone()))
        } else if cert.public_key.algorithm.algorithm.is_ec_public_key() {
            Ok((PublicKeyKind::EcdsaP256, cert.public_key.public_key.clone()))
        } else {
            Err(OnionError::CertificateError)
        }
    }
}
