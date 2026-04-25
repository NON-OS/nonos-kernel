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

use super::super::types::PublicKeyKind;
use crate::network::onion::OnionError;
use alloc::vec::Vec;

pub struct X509;

impl X509 {
    pub fn parse_der(
        der: &[u8],
    ) -> Result<crate::network::onion::nonos_crypto::X509Certificate, OnionError> {
        crate::network::onion::nonos_crypto::X509::parse_der(der)
    }

    pub fn verify_self_signed(
        cert: &crate::network::onion::nonos_crypto::X509Certificate,
    ) -> Result<(), OnionError> {
        crate::network::onion::nonos_crypto::X509::verify_self_signed(cert)
    }

    pub fn check_basic_constraints_end_entity(
        cert: &crate::network::onion::nonos_crypto::X509Certificate,
    ) -> Result<(), OnionError> {
        crate::network::onion::nonos_crypto::X509::check_basic_constraints_end_entity(cert)
    }

    pub fn check_time_validity(
        cert: &crate::network::onion::nonos_crypto::X509Certificate,
        now_ms: u64,
    ) -> Result<(), OnionError> {
        crate::network::onion::nonos_crypto::X509::check_time_validity(cert, now_ms)
    }

    pub fn public_key_info(
        cert: &crate::network::onion::nonos_crypto::X509Certificate,
    ) -> Result<(PublicKeyKind, Vec<u8>), OnionError> {
        let (crypto_kind, data) = crate::network::onion::nonos_crypto::X509::public_key_info(cert)?;
        let tls_kind = match crypto_kind {
            crate::network::onion::nonos_crypto::PublicKeyKind::Rsa => PublicKeyKind::Rsa,
            crate::network::onion::nonos_crypto::PublicKeyKind::Ed25519 => PublicKeyKind::Ed25519,
            crate::network::onion::nonos_crypto::PublicKeyKind::EcdsaP256 => {
                PublicKeyKind::EcdsaP256
            }
            crate::network::onion::nonos_crypto::PublicKeyKind::EcdsaP384 => {
                PublicKeyKind::EcdsaP384
            }
            crate::network::onion::nonos_crypto::PublicKeyKind::X25519 => PublicKeyKind::X25519,
        };
        Ok((tls_kind, data))
    }
}
