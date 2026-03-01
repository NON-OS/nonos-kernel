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

use crate::capabilities::token::signing_key;

use super::error::ResourceError;
use super::material::{compute_signature, token_material};
use super::token::ResourceToken;

pub fn verify_resource_token(tok: &ResourceToken) -> bool {
    let Some(key) = signing_key() else {
        return false;
    };

    let mat = token_material(tok.owner_module, &tok.original_quota, tok.nonce);
    let expected = compute_signature(key, &mat);

    tok.signature == expected
}

pub fn verify_resource_token_strict(tok: &ResourceToken) -> Result<(), ResourceError> {
    if tok.is_expired() {
        return Err(ResourceError::TokenExpired);
    }

    let Some(key) = signing_key() else {
        return Err(ResourceError::MissingSigningKey);
    };

    let mat = token_material(tok.owner_module, &tok.original_quota, tok.nonce);
    let expected = compute_signature(key, &mat);

    if tok.signature != expected {
        return Err(ResourceError::InvalidSignature);
    }

    Ok(())
}
