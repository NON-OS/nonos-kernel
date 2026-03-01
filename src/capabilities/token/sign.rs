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

use crate::capabilities::bits::caps_to_bits;

use super::material::{mac64, token_material};
use super::nonce::default_nonce;
use super::signing_key::signing_key;
use super::types::CapabilityToken;

pub fn sign_token(tok: &mut CapabilityToken) -> Result<(), &'static str> {
    let key = signing_key().ok_or("No signing key")?;
    if tok.nonce == 0 {
        tok.nonce = default_nonce();
    }

    let mat = token_material(
        tok.owner_module,
        caps_to_bits(&tok.permissions),
        tok.expires_at_ms.unwrap_or(0),
        tok.nonce,
    );
    tok.signature = mac64(key, &mat);
    Ok(())
}
