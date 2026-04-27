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

use super::super::types::{ObjectIdentifier, PublicKeyKind, X509Certificate};
use super::oid::parse_oid;
use super::x509::X509;
use crate::network::onion::OnionError;
use alloc::vec::Vec;

impl X509 {
    pub fn public_key_info(cert: &X509Certificate) -> Result<(PublicKeyKind, Vec<u8>), OnionError> {
        if cert.public_key.algorithm.algorithm.is_rsa_encryption() {
            Ok((PublicKeyKind::Rsa, cert.public_key.public_key.clone()))
        } else if cert.public_key.algorithm.algorithm.is_ed25519() {
            Ok((PublicKeyKind::Ed25519, cert.public_key.public_key.clone()))
        } else if cert.public_key.algorithm.algorithm.is_ec_public_key() {
            let kind = ec_curve_kind(&cert.public_key.algorithm.parameters);
            Ok((kind, cert.public_key.public_key.clone()))
        } else {
            Err(OnionError::CertificateError)
        }
    }
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
