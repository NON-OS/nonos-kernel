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

use super::hostname::verify_hostname;
use crate::network::onion::OnionError;
use crate::sys::serial;

pub(super) fn verify_hostname_if_needed(
    end_entity: &crate::network::onion::nonos_crypto::X509Certificate,
    sni: &str,
) -> bool {
    let mut hostname_ok = true;
    if !sni.is_empty() {
        serial::println(b"[CERT] verifying hostname");
        if verify_hostname(end_entity, sni).is_err() {
            serial::println(b"[CERT] WARNING: hostname verify failed");
            hostname_ok = false;
        } else {
            serial::println(b"[CERT] hostname OK");
        }
    }
    hostname_ok
}

pub(super) fn check_final_result(
    chain_verified: bool,
    root_trusted: bool,
    hostname_ok: bool,
) -> Result<(), OnionError> {
    if !chain_verified {
        serial::println(b"[CERT] ERROR: chain verification failed");
        return Err(OnionError::CertificateSignatureFailed);
    }
    if !root_trusted {
        serial::println(b"[CERT] ERROR: no trusted root found");
        return Err(OnionError::CertificateNoTrustedRoot);
    }
    if !hostname_ok {
        serial::println(b"[CERT] ERROR: hostname mismatch");
        return Err(OnionError::CertificateHostnameMismatch);
    }
    serial::println(b"[CERT] connection allowed");
    Ok(())
}
