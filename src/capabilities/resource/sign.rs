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

pub fn sign_resource_token(tok: &mut ResourceToken) -> Result<(), ResourceError> {
    let key = signing_key().ok_or(ResourceError::MissingSigningKey)?;

    let mat = token_material(tok.owner_module, &tok.original_quota, tok.nonce);
    tok.signature = compute_signature(key, &mat);

    Ok(())
}
