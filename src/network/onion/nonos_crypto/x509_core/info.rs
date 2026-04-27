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
use super::super::types::{ObjectIdentifier, PublicKeyInfo, PublicKeyKind, X509Certificate};
use super::super::x509_der::DerParser;
use super::spki::parse_subject_public_key_info;
use super::x509::X509;
use super::oid::parse_oid;

impl X509 {
    pub fn public_key_info(cert: &X509Certificate) -> Result<(PublicKeyKind, Vec<u8>), OnionError> {
        let kind = public_key_kind(&cert.public_key)?;
        Ok((kind, cert.public_key.public_key.clone()))
    }

    pub fn public_key_info_der(der: &[u8]) -> Result<(PublicKeyKind, Vec<u8>, Vec<u8>), OnionError> {
        let mut parser = DerParser::new(der);
        parser.expect_sequence()?;
        let outer_len = parser.read_length()?;
        let outer_end = parser.offset.checked_add(outer_len).ok_or(OnionError::CryptoError)?;
        if outer_end > der.len() { return Err(OnionError::CryptoError); }
        parser.expect_sequence()?;
        let tbs_len = parser.read_length()?;
        let tbs_end = parser.offset.checked_add(tbs_len).ok_or(OnionError::CryptoError)?;
        if tbs_end > outer_end { return Err(OnionError::CryptoError); }
        skip_tbs_prefix(&mut parser, tbs_end)?;
        let public_key = parse_subject_public_key_info(&mut parser)?;
        if parser.offset > tbs_end { return Err(OnionError::CryptoError); }
        let kind = public_key_kind(&public_key)?;
        Ok((kind, public_key.public_key, public_key.raw_spki))
    }
}

fn public_key_kind(public_key: &PublicKeyInfo) -> Result<PublicKeyKind, OnionError> {
    if public_key.algorithm.algorithm.is_rsa_encryption() {
        Ok(PublicKeyKind::Rsa)
    } else if public_key.algorithm.algorithm.is_ed25519() {
        Ok(PublicKeyKind::Ed25519)
    } else if public_key.algorithm.algorithm.is_ec_public_key() {
        Ok(ec_curve_kind(&public_key.algorithm.parameters))
    } else {
        Err(OnionError::CertificateError)
    }
}

fn skip_tbs_prefix(parser: &mut DerParser, tbs_end: usize) -> Result<(), OnionError> {
    if parser.peek_tag() == Some(0xA0) { skip_tbs_structure(parser, tbs_end)?; }
    for _ in 0..5 { skip_tbs_structure(parser, tbs_end)?; }
    Ok(())
}

fn skip_tbs_structure(parser: &mut DerParser, tbs_end: usize) -> Result<(), OnionError> {
    if parser.offset >= tbs_end { return Err(OnionError::CryptoError); }
    parser.skip_structure()?;
    if parser.offset > tbs_end { return Err(OnionError::CryptoError); }
    Ok(())
}

fn ec_curve_kind(params: &Option<Vec<u8>>) -> PublicKeyKind {
    if let Some(p) = params {
        if p.len() >= 2 && p[0] == 0x06 {
            let oid_len = p[1] as usize;
            if p.len() >= 2 + oid_len {
                if let Ok(oid) = parse_oid(&p[2..2 + oid_len]) {
                    if oid.components == ObjectIdentifier::SECP384R1 {
                        return PublicKeyKind::EcdsaP384;
                    }
                }
            }
        }
    }
    PublicKeyKind::EcdsaP256
}
