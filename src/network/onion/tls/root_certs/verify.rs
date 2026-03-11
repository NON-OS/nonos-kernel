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
use super::store::TRUSTED_ROOTS;

pub fn is_trusted_root(cert: &X509Certificate) -> bool {
    let spki_hash = sha256(&cert.public_key.raw_spki);
    for root in TRUSTED_ROOTS {
        if root.spki_sha256 == spki_hash {
            return true;
        }
    }
    false
}

pub fn verify_trusted_root(chain: &[X509Certificate]) -> Result<(), OnionError> {
    if chain.is_empty() {
        return Err(OnionError::CertificateError);
    }
    let root = &chain[chain.len() - 1];
    if root.issuer_der != root.subject_der {
        return Err(OnionError::CertificateError);
    }
    if is_trusted_root(root) {
        return Ok(());
    }
    Err(OnionError::CertificateError)
}

pub fn trusted_root_count() -> usize {
    TRUSTED_ROOTS.len()
}
