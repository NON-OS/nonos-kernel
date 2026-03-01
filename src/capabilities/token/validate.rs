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

use super::revocation::is_revoked;
use super::types::CapabilityToken;
use super::verify::verify_token;

pub fn is_token_valid(tok: &CapabilityToken) -> bool {
    verify_token(tok) && tok.not_expired() && !is_revoked(tok.owner_module, tok.nonce)
}

pub fn is_token_signature_valid(tok: &CapabilityToken) -> bool {
    verify_token(tok)
}

pub fn is_token_not_revoked(tok: &CapabilityToken) -> bool {
    !is_revoked(tok.owner_module, tok.nonce)
}

pub fn validate_token_full(tok: &CapabilityToken) -> Result<(), &'static str> {
    if !verify_token(tok) {
        return Err("Invalid signature");
    }
    if !tok.not_expired() {
        return Err("Token expired");
    }
    if is_revoked(tok.owner_module, tok.nonce) {
        return Err("Token revoked");
    }
    Ok(())
}
