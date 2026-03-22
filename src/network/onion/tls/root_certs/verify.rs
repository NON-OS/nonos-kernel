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
use crate::network::onion::nonos_crypto::X509Certificate;
use crate::crypto::hash::unified::sha256;
use crate::sys::serial;
use super::store::TRUSTED_ROOT_GROUPS;

pub fn is_trusted_root(cert: &X509Certificate) -> bool {
    let spki_hash = sha256(&cert.public_key.raw_spki);
    for group in TRUSTED_ROOT_GROUPS {
        for root in *group {
            if root.spki_sha256 == spki_hash {
                return true;
            }
        }
    }
    false
}

pub fn verify_trusted_root(chain: &[X509Certificate]) -> Result<(), OnionError> {
    if chain.is_empty() {
        return Err(OnionError::CertificateError);
    }
    let root = &chain[chain.len() - 1];
    // Check the topmost cert's SPKI against our trust store.
    // Do NOT require issuer == subject: the server may send a cross-signed
    // version of the root (e.g. GTS Root R1 cross-signed by GlobalSign)
    // whose issuer differs from its subject but whose key is trusted.
    if is_trusted_root(root) {
        return Ok(());
    }
    // Log the unmatched SPKI hash for debugging (first 8 bytes)
    let hash = sha256(&root.public_key.raw_spki);
    serial::print(b"[CERT] untrusted topmost SPKI(first8): ");
    for &b in hash.iter().take(8) {
        serial::print_hex(b as u64);
        serial::print(b" ");
    }
    serial::println(b"");
    Err(OnionError::CertificateError)
}

pub fn trusted_root_count() -> usize {
    TRUSTED_ROOT_GROUPS.iter().map(|g| g.len()).sum()
}
