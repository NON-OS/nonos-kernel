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

use crate::capabilities::types::Capability;

use super::sign::sign_token;
use super::types::CapabilityToken;

pub fn create_token(
    owner: u64,
    caps: &[Capability],
    ttl_ms: Option<u64>,
) -> Result<CapabilityToken, &'static str> {
    let exp = ttl_ms.map(|t| crate::time::timestamp_millis().saturating_add(t));
    let mut tok = CapabilityToken {
        owner_module: owner,
        permissions: caps.to_vec(),
        expires_at_ms: exp,
        nonce: 0,
        signature: [0u8; 64],
    };
    sign_token(&mut tok)?;
    Ok(tok)
}

pub fn create_token_with_nonce(
    owner: u64,
    caps: &[Capability],
    ttl_ms: Option<u64>,
    nonce: u64,
) -> Result<CapabilityToken, &'static str> {
    let exp = ttl_ms.map(|t| crate::time::timestamp_millis().saturating_add(t));
    let mut tok = CapabilityToken {
        owner_module: owner,
        permissions: caps.to_vec(),
        expires_at_ms: exp,
        nonce,
        signature: [0u8; 64],
    };
    sign_token(&mut tok)?;
    Ok(tok)
}
