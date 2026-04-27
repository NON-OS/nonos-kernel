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
use crate::sys::serial;
use crate::network::onion::nonos_crypto::{check_eku_server_auth, check_leaf_key_usage};
use super::traits::CertVerifier;
use super::x509_wrap::X509;
use super::https_check::{verify_hostname_if_needed, check_final_result};

const REVOCATION_CT_POLICY: &[u8] = b"unsupported-soft-fail";

pub struct HttpsCertVerifier;
pub static HTTPS_CERT_VERIFIER: HttpsCertVerifier = HttpsCertVerifier;

impl CertVerifier for HttpsCertVerifier {
    fn verify(&self, chain_der: &[Vec<u8>], sni: &str) -> Result<(), OnionError> {
        serial::println(b"[CERT] HttpsCertVerifier::verify");
        if chain_der.is_empty() {
            serial::println(b"[CERT] ERROR: empty chain");
            return Err(OnionError::AuthenticationFailed);
        }
        let now_ms = crate::time::unix_timestamp() * 1000;
        serial::print(b"[CERT] now_ms=");
        serial::print_dec(now_ms);
        serial::println(b"");
        let mut chain = Vec::new();
        for (i, der) in chain_der.iter().enumerate() {
            serial::print(b"[CERT] parsing cert ");
            serial::print_dec(i as u64);
            serial::print(b" (");
            serial::print_dec(der.len() as u64);
            serial::println(b" bytes)");
            match X509::parse_der(der) {
                Ok(c) => chain.push(c),
                Err(e) => {
                    serial::println(b"[CERT] ERROR: parse failed");
                    return Err(e);
                }
            }
        }
        let end_entity = &chain[0];
        serial::println(b"[CERT] checking time validity");
        if let Err(e) = X509::check_time_validity(end_entity, now_ms) {
            serial::println(b"[CERT] ERROR: time validity failed");
            return Err(e);
        }
        serial::println(b"[CERT] time validity OK");
        // Policy enforcement: EKU must include ServerAuth (if present)
        if check_eku_server_auth(end_entity).is_err() {
            serial::println(b"[CERT] ERROR: EKU check failed (no ServerAuth)");
            return Err(crate::network::onion::OnionError::CertificatePolicyFailed);
        }
        // Policy enforcement: KU must include digitalSignature (if present)
        if check_leaf_key_usage(end_entity).is_err() {
            serial::println(b"[CERT] ERROR: KU check failed (no digitalSignature)");
            return Err(crate::network::onion::OnionError::CertificatePolicyFailed);
        }
        serial::println(b"[CERT] leaf policy checks OK");
        serial::print(b"[CERT] revocation/ct policy=");
        serial::println(REVOCATION_CT_POLICY);
        let (chain_verified, root_trusted) = verify_chain_and_root(&chain, now_ms);
        let hostname_ok = verify_hostname_if_needed(end_entity, sni);
        check_final_result(chain_verified, root_trusted, hostname_ok)
    }
}

fn verify_chain_and_root(chain: &[crate::network::onion::nonos_crypto::X509Certificate], now_ms: u64) -> (bool, bool) {
    let mut chain_verified = true;
    let mut root_trusted = true;
    if chain.len() > 1 {
        serial::println(b"[CERT] verifying chain");
        if crate::network::onion::nonos_crypto::X509::verify_chain(chain, now_ms).is_err() {
            serial::println(b"[CERT] WARNING: chain verify failed");
            chain_verified = false;
        } else {
            serial::println(b"[CERT] chain verify OK");
        }
        serial::println(b"[CERT] verifying root anchor");
        match super::super::root_certs::verify_chain_to_root(chain) {
            Ok(root) => {
                serial::print(b"[CERT] trusted root: ");
                let name_bytes = root.name.as_bytes();
                let print_len = if name_bytes.len() > 40 { 40 } else { name_bytes.len() };
                serial::print(&name_bytes[..print_len]);
                serial::println(b"");
            }
            Err(_) => {
                serial::println(b"[CERT] WARNING: root not trusted");
                root_trusted = false;
            }
        }
    } else {
        serial::println(b"[CERT] verifying self-signed");
        if X509::verify_self_signed(&chain[0]).is_err() {
            serial::println(b"[CERT] WARNING: self-signed verify failed");
            chain_verified = false;
        } else {
            serial::println(b"[CERT] self-signed OK");
        }
    }
    (chain_verified, root_trusted)
}
