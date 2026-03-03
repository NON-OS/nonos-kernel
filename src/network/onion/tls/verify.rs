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
use spin::Once;
use crate::network::onion::OnionError;
use super::types::PublicKeyKind;

pub trait CertVerifier: Sync + Send {
    fn verify(&self, chain_der: &[Vec<u8>], sni: &str) -> Result<(), OnionError>;
}

static CERT_VERIFIER: Once<&'static dyn CertVerifier> = Once::new();

pub fn init_tls_cert_verifier(v: &'static dyn CertVerifier) {
    CERT_VERIFIER.call_once(|| v);
}

pub fn get_cert_verifier() -> Option<&'static dyn CertVerifier> {
    CERT_VERIFIER.get().copied()
}

pub struct StrictTorLinkVerifier;
pub static STRICT_TOR_LINK_VERIFIER: StrictTorLinkVerifier = StrictTorLinkVerifier;

impl CertVerifier for StrictTorLinkVerifier {
    fn verify(&self, chain_der: &[Vec<u8>], _sni: &str) -> Result<(), OnionError> {
        if chain_der.len() != 1 {
            return Err(OnionError::AuthenticationFailed);
        }
        let cert = X509::parse_der(&chain_der[0])?;
        X509::verify_self_signed(&cert)?;
        X509::check_basic_constraints_end_entity(&cert)?;
        let now_ms = crate::time::timestamp_millis();
        X509::check_time_validity(&cert, now_ms)?;
        Ok(())
    }
}

pub struct X509;

impl X509 {
    pub fn parse_der(der: &[u8]) -> Result<crate::network::onion::nonos_crypto::X509Certificate, OnionError> {
        crate::network::onion::nonos_crypto::X509::parse_der(der)
    }

    pub fn verify_self_signed(cert: &crate::network::onion::nonos_crypto::X509Certificate) -> Result<(), OnionError> {
        crate::network::onion::nonos_crypto::X509::verify_self_signed(cert)
    }

    pub fn check_basic_constraints_end_entity(cert: &crate::network::onion::nonos_crypto::X509Certificate) -> Result<(), OnionError> {
        crate::network::onion::nonos_crypto::X509::check_basic_constraints_end_entity(cert)
    }

    pub fn check_time_validity(cert: &crate::network::onion::nonos_crypto::X509Certificate, now_ms: u64) -> Result<(), OnionError> {
        crate::network::onion::nonos_crypto::X509::check_time_validity(cert, now_ms)
    }

    pub fn public_key_info(cert: &crate::network::onion::nonos_crypto::X509Certificate) -> Result<(PublicKeyKind, Vec<u8>), OnionError> {
        let (crypto_kind, data) = crate::network::onion::nonos_crypto::X509::public_key_info(cert)?;
        let tls_kind = match crypto_kind {
            crate::network::onion::nonos_crypto::PublicKeyKind::Rsa => PublicKeyKind::Rsa,
            crate::network::onion::nonos_crypto::PublicKeyKind::Ed25519 => PublicKeyKind::Ed25519,
            crate::network::onion::nonos_crypto::PublicKeyKind::X25519 => PublicKeyKind::X25519,
        };
        Ok((tls_kind, data))
    }
}

pub fn init_tls_stack_production(provider: &'static dyn super::crypto_provider::TlsCrypto) -> Result<(), OnionError> {
    super::crypto_provider::init_tls_crypto(provider);
    init_tls_cert_verifier(&STRICT_TOR_LINK_VERIFIER);
    Ok(())
}

pub struct HttpsCertVerifier;
pub static HTTPS_CERT_VERIFIER: HttpsCertVerifier = HttpsCertVerifier;

impl CertVerifier for HttpsCertVerifier {
    fn verify(&self, chain_der: &[Vec<u8>], sni: &str) -> Result<(), OnionError> {
        if chain_der.is_empty() {
            return Err(OnionError::AuthenticationFailed);
        }

        let cert = X509::parse_der(&chain_der[0])?;

        X509::check_time_validity(&cert, crate::time::timestamp_millis())?;

        if chain_der.len() == 1 {
            let _ = X509::verify_self_signed(&cert);
        }

        if !sni.is_empty() {
            if let Err(_) = verify_hostname(&cert, sni) {
                crate::warn!("HTTPS: Certificate hostname mismatch for {}", sni);
            }
        }

        Ok(())
    }
}

fn verify_hostname(cert: &crate::network::onion::nonos_crypto::X509Certificate, hostname: &str) -> Result<(), OnionError> {
    if let Some(san_names) = crate::network::onion::nonos_crypto::X509::get_san_dns_names(cert) {
        for name in san_names {
            if matches_hostname(&name, hostname) {
                return Ok(());
            }
        }
    }

    if let Some(cn) = crate::network::onion::nonos_crypto::X509::get_subject_cn(cert) {
        if matches_hostname(&cn, hostname) {
            return Ok(());
        }
    }

    Err(OnionError::AuthenticationFailed)
}

fn matches_hostname(cert_name: &str, hostname: &str) -> bool {
    let cert_name = cert_name.to_ascii_lowercase();
    let hostname = hostname.to_ascii_lowercase();

    if cert_name == hostname {
        return true;
    }

    if cert_name.starts_with("*.") {
        let cert_domain = &cert_name[2..];
        if let Some(host_domain) = hostname.strip_prefix(|c: char| c != '.').and_then(|s| s.strip_prefix('.')) {
            return host_domain == cert_domain;
        }
        if hostname == cert_domain {
            return true;
        }
    }

    false
}
