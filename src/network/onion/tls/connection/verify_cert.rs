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
use super::types::{TLSConnection, HandshakePhase};
use super::super::types::PublicKeyKind;
use super::super::protocol::build_cert_verify_context;
use super::super::verify::X509;
use super::super::crypto_provider::crypto;

impl TLSConnection {
    pub(super) fn verify_certificate_signature(&mut self) -> Result<(), OnionError> {
        let alg = self.cert_verify_alg.ok_or_else(|| { self.phase = HandshakePhase::Failed; OnionError::AuthenticationFailed })?;
        let leaf = X509::parse_der(&self.server_certs[0])?;
        let (pk_kind, pk_bytes) = X509::public_key_info(&leaf)?;
        let hl = self.suite.hash_len();
        let to_be_signed = build_cert_verify_context(&self.cert_verify_hash[..hl]);
        let c = crypto();
        let ok = match alg {
            0x0807 => pk_kind == PublicKeyKind::Ed25519 && c.verify_ed25519(&pk_bytes, &to_be_signed, &self.cert_verify_sig),
            0x0804 => pk_kind == PublicKeyKind::Rsa && c.verify_rsa_pss_sha256(&pk_bytes, &to_be_signed, &self.cert_verify_sig),
            0x0805 => pk_kind == PublicKeyKind::Rsa && c.verify_rsa_pss_sha384(&pk_bytes, &to_be_signed, &self.cert_verify_sig),
            0x0401 => pk_kind == PublicKeyKind::Rsa && c.verify_rsa_pkcs1v15_sha256(&pk_bytes, &to_be_signed, &self.cert_verify_sig),
            0x0501 => pk_kind == PublicKeyKind::Rsa && c.verify_rsa_pkcs1v15_sha384(&pk_bytes, &to_be_signed, &self.cert_verify_sig),
            0x0403 => pk_kind == PublicKeyKind::EcdsaP256 && c.verify_ecdsa_p256_sha256(&pk_bytes, &to_be_signed, &self.cert_verify_sig),
            0x0503 => pk_kind == PublicKeyKind::EcdsaP384 && c.verify_ecdsa_p384_sha384(&pk_bytes, &to_be_signed, &self.cert_verify_sig),
            _ => false,
        };
        if !ok { self.phase = HandshakePhase::Failed; return Err(OnionError::AuthenticationFailed); }
        Ok(())
    }
}
