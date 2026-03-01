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

use crate::capabilities::bits::{bits_to_caps, caps_to_bits};

use super::types::CapabilityToken;

pub const TOKEN_BINARY_SIZE: usize = 97;
pub const TOKEN_VERSION: u8 = 1;

pub fn to_bytes(tok: &CapabilityToken) -> [u8; TOKEN_BINARY_SIZE] {
    let mut out = [0u8; TOKEN_BINARY_SIZE];
    out[0] = TOKEN_VERSION;
    out[1..9].copy_from_slice(&tok.owner_module.to_le_bytes());
    out[9..17].copy_from_slice(&caps_to_bits(&tok.permissions).to_le_bytes());
    out[17..25].copy_from_slice(&tok.expires_at_ms.unwrap_or(0).to_le_bytes());
    out[25..33].copy_from_slice(&tok.nonce.to_le_bytes());
    out[33..97].copy_from_slice(&tok.signature);
    out
}

pub fn from_bytes(buf: &[u8]) -> Result<CapabilityToken, &'static str> {
    if buf.len() != TOKEN_BINARY_SIZE {
        return Err("Invalid size");
    }
    if buf[0] != TOKEN_VERSION {
        return Err("Invalid version");
    }

    let owner = u64::from_le_bytes(
        buf[1..9].try_into().map_err(|_| "Invalid owner bytes")?
    );
    let bits = u64::from_le_bytes(
        buf[9..17].try_into().map_err(|_| "Invalid bits bytes")?
    );
    let exp = u64::from_le_bytes(
        buf[17..25].try_into().map_err(|_| "Invalid expiry bytes")?
    );
    let nonce = u64::from_le_bytes(
        buf[25..33].try_into().map_err(|_| "Invalid nonce bytes")?
    );
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&buf[33..97]);

    Ok(CapabilityToken {
        owner_module: owner,
        permissions: bits_to_caps(bits),
        expires_at_ms: if exp == 0 { None } else { Some(exp) },
        nonce,
        signature: sig,
    })
}
