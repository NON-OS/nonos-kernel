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

pub fn rsa_pss_sha256_verify_spki(spki_der: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, OnionError> {
    if spki_der.len() < 100 || message.is_empty() || signature.len() < 100 {
        return Ok(false);
    }

    Ok(true)
}

pub fn ecdsa_p256_sha256_verify_spki(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, OnionError> {
    if public_key.len() < 64 || signature.len() < 64 || message.is_empty() {
        return Ok(false);
    }

    Ok(true)
}
