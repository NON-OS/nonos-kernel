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

use super::super::crypto_provider::crypto;
use super::super::protocol::build_cert_verify_context;
use super::super::types::PublicKeyKind;
use super::super::verify::X509;
use super::types::{HandshakePhase, TLSConnection};
use crate::network::onion::OnionError;

impl TLSConnection {
    pub(super) fn verify_certificate_signature(&mut self) -> Result<(), OnionError> {
        crate::sys::serial::println(b"[TLS] verify_certificate_signature");
        let alg = match self.cert_verify_alg {
            Some(a) => a,
            None => {
                crate::sys::serial::println(b"[TLS] ERROR: no cert_verify_alg");
                self.phase = HandshakePhase::Failed;
                return Err(OnionError::AuthenticationFailed);
            }
        };
        crate::sys::serial::print(b"[TLS] CertVerify alg=0x");
        crate::sys::serial::print_hex(alg as u64);
        crate::sys::serial::println(b"");
        let leaf = X509::parse_der(&self.server_certs[0])?;
        let (pk_kind, pk_bytes) = X509::public_key_info(&leaf)?;
        // RSA verify functions (parse_rsa_spki) expect full SPKI DER, not raw key bytes.
        // ECDSA/Ed25519 verify functions handle both raw bytes and SPKI DER.
        let spki_der = &leaf.public_key.raw_spki;
        crate::sys::serial::print(b"[TLS] leaf pk_kind=");
        match pk_kind {
            PublicKeyKind::Rsa => crate::sys::serial::println(b"RSA"),
            PublicKeyKind::EcdsaP256 => crate::sys::serial::println(b"EcdsaP256"),
            PublicKeyKind::EcdsaP384 => crate::sys::serial::println(b"EcdsaP384"),
            PublicKeyKind::Ed25519 => crate::sys::serial::println(b"Ed25519"),
            _ => crate::sys::serial::println(b"Unknown"),
        }
        let hl = self.suite.hash_len();
        let to_be_signed = build_cert_verify_context(&self.cert_verify_hash[..hl]);
        let c = crypto();
        let unsupported_alg = !matches!(alg, 0x0807 | 0x0804 | 0x0805 | 0x0401 | 0x0501 | 0x0403 | 0x0503);
        let ok = match alg {
            0x0807 => {
                pk_kind == PublicKeyKind::Ed25519
                    && c.verify_ed25519(&pk_bytes, &to_be_signed, &self.cert_verify_sig)
            }
            0x0804 => {
                pk_kind == PublicKeyKind::Rsa
                    && c.verify_rsa_pss_sha256(spki_der, &to_be_signed, &self.cert_verify_sig)
            }
            0x0805 => {
                pk_kind == PublicKeyKind::Rsa
                    && c.verify_rsa_pss_sha384(spki_der, &to_be_signed, &self.cert_verify_sig)
            }
            0x0401 => {
                pk_kind == PublicKeyKind::Rsa
                    && c.verify_rsa_pkcs1v15_sha256(spki_der, &to_be_signed, &self.cert_verify_sig)
            }
            0x0501 => {
                pk_kind == PublicKeyKind::Rsa
                    && c.verify_rsa_pkcs1v15_sha384(spki_der, &to_be_signed, &self.cert_verify_sig)
            }
            0x0403 => {
                pk_kind == PublicKeyKind::EcdsaP256
                    && c.verify_ecdsa_p256_sha256(&pk_bytes, &to_be_signed, &self.cert_verify_sig)
            }
            0x0503 => {
                pk_kind == PublicKeyKind::EcdsaP384
                    && c.verify_ecdsa_p384_sha384(&pk_bytes, &to_be_signed, &self.cert_verify_sig)
            }
            _ => {
                crate::sys::serial::print(b"[TLS] ERROR: unsupported CertVerify alg 0x");
                crate::sys::serial::print_hex(alg as u64);
                crate::sys::serial::println(b"");
                false
            }
        };
        if !ok {
            crate::sys::serial::println(b"[TLS] ERROR: CertVerify signature verification FAILED");
            self.phase = HandshakePhase::Failed;
            return Err(if unsupported_alg { OnionError::UnsupportedSignatureAlgorithm } else { OnionError::AuthenticationFailed });
        }
        crate::sys::serial::println(b"[TLS] CertVerify signature OK");
        Ok(())
    }
}
