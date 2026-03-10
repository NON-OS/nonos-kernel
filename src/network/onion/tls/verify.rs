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
        let now_ms = crate::time::unix_timestamp() * 1000;
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
            crate::network::onion::nonos_crypto::PublicKeyKind::EcdsaP256 => PublicKeyKind::EcdsaP256,
            crate::network::onion::nonos_crypto::PublicKeyKind::X25519 => PublicKeyKind::X25519,
        };
        Ok((tls_kind, data))
    }
}

pub fn init_tls_stack_production(provider: &'static dyn super::crypto_provider::TlsCrypto) -> Result<(), OnionError> {
    super::crypto_provider::init_tls_crypto(provider);
    init_tls_cert_verifier(&HTTPS_CERT_VERIFIER);
    Ok(())
}

pub struct HttpsCertVerifier;
pub static HTTPS_CERT_VERIFIER: HttpsCertVerifier = HttpsCertVerifier;

impl CertVerifier for HttpsCertVerifier {
    fn verify(&self, chain_der: &[Vec<u8>], sni: &str) -> Result<(), OnionError> {
        crate::sys::serial::println(b"[CERT] HttpsCertVerifier::verify");

        if chain_der.is_empty() {
            crate::sys::serial::println(b"[CERT] ERROR: empty chain");
            return Err(OnionError::AuthenticationFailed);
        }

        let now_ms = crate::time::unix_timestamp() * 1000;
        crate::sys::serial::print(b"[CERT] now_ms=");
        crate::sys::serial::print_dec(now_ms);
        crate::sys::serial::println(b"");

        let mut chain = Vec::new();

        for (i, der) in chain_der.iter().enumerate() {
            crate::sys::serial::print(b"[CERT] parsing cert ");
            crate::sys::serial::print_dec(i as u64);
            crate::sys::serial::print(b" (");
            crate::sys::serial::print_dec(der.len() as u64);
            crate::sys::serial::println(b" bytes)");
            match X509::parse_der(der) {
                Ok(c) => chain.push(c),
                Err(e) => {
                    crate::sys::serial::println(b"[CERT] ERROR: parse failed");
                    return Err(e);
                }
            }
        }

        let end_entity = &chain[0];

        crate::sys::serial::println(b"[CERT] checking time validity");
        if let Err(e) = X509::check_time_validity(end_entity, now_ms) {
            crate::sys::serial::println(b"[CERT] ERROR: time validity failed");
            return Err(e);
        }
        crate::sys::serial::println(b"[CERT] time validity OK");

        if chain.len() > 1 {
            crate::sys::serial::println(b"[CERT] verifying chain");
            if let Err(e) = crate::network::onion::nonos_crypto::X509::verify_chain(&chain, now_ms) {
                crate::sys::serial::println(b"[CERT] ERROR: chain verify failed");
                return Err(e);
            }
            crate::sys::serial::println(b"[CERT] chain verify OK");
        } else {
            crate::sys::serial::println(b"[CERT] verifying self-signed");
            if let Err(e) = X509::verify_self_signed(end_entity) {
                crate::sys::serial::println(b"[CERT] ERROR: self-signed verify failed");
                return Err(e);
            }
            crate::sys::serial::println(b"[CERT] self-signed OK");
        }

        if !sni.is_empty() {
            crate::sys::serial::println(b"[CERT] verifying hostname");
            if let Err(e) = verify_hostname(end_entity, sni) {
                crate::sys::serial::println(b"[CERT] ERROR: hostname verify failed");
                return Err(e);
            }
            crate::sys::serial::println(b"[CERT] hostname OK");
        }

        crate::sys::serial::println(b"[CERT] all checks passed");
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
