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
use super::super::types::{PublicKeyKind, X509Certificate};
use super::x509::X509;

impl X509 {
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
