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

pub(super) fn verify_hostname(cert: &crate::network::onion::nonos_crypto::X509Certificate, hostname: &str) -> Result<(), OnionError> {
    if let Some(san_names) = crate::network::onion::nonos_crypto::X509::get_san_dns_names(cert) {
        // RFC 6125 §6.4.4: If SAN is present, CN MUST NOT be checked
        for name in san_names {
            if matches_hostname(&name, hostname) {
                return Ok(());
            }
        }
        return Err(OnionError::AuthenticationFailed);
    }
    // No SAN extension — fall back to CN (legacy behavior)
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
