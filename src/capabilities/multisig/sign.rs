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

use super::error::MultiSigError;
use super::material::{compute_signature, signature_material};
use super::token::MultiSigToken;

pub fn add_signature(
    token: &mut MultiSigToken,
    signer_id: u64,
    key: &[u8; 32],
) -> Result<(), MultiSigError> {
    if !token.is_authorized(signer_id) {
        return Err(MultiSigError::UnauthorizedSigner { signer_id });
    }

    if token.has_signed(signer_id) {
        return Err(MultiSigError::DuplicateSigner { signer_id });
    }

    if token.is_expired() {
        return Err(MultiSigError::TokenExpired);
    }

    let mat = signature_material(token, signer_id);
    let sig = compute_signature(key, &mat);

    token.signatures.push((signer_id, sig));
    Ok(())
}

pub fn remove_signature(token: &mut MultiSigToken, signer_id: u64) -> bool {
    let original_len = token.signatures.len();
    token.signatures.retain(|(id, _)| *id != signer_id);
    token.signatures.len() < original_len
}

pub fn clear_signatures(token: &mut MultiSigToken) {
    token.signatures.clear();
}
