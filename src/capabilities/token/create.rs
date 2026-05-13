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

use super::nonce::{default_nonce, secure_nonce_128};
use super::sign::sign_token;
use super::types::CapabilityToken;

const ERR_BOOT_NONCE: &str = "boot session nonce not initialized";

pub fn create_token(
    owner: u64,
    caps: &[Capability],
    ttl_ms: Option<u64>,
) -> Result<CapabilityToken, &'static str> {
    let boot_nonce = crate::security::boot_session::nonce().ok_or(ERR_BOOT_NONCE)?;
    let exp = ttl_ms.map(|t| crate::time::timestamp_millis().saturating_add(t));
    let mut tok = CapabilityToken {
        owner_module: owner,
        permissions: caps.to_vec(),
        expires_at_ms: exp,
        nonce: default_nonce(),
        signature: [0u8; 64],
        token_id: default_nonce(),
        subject_capsule_id: owner as u32,
        subject_asid: 0,
        subject_measurement: [0u8; 32],
        boot_session_nonce: boot_nonce,
        revocation_epoch: 0,
        delegation_depth: 0,
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
    let boot_nonce = crate::security::boot_session::nonce().ok_or(ERR_BOOT_NONCE)?;
    let exp = ttl_ms.map(|t| crate::time::timestamp_millis().saturating_add(t));
    let mut tok = CapabilityToken {
        owner_module: owner,
        permissions: caps.to_vec(),
        expires_at_ms: exp,
        nonce,
        signature: [0u8; 64],
        token_id: default_nonce(),
        subject_capsule_id: owner as u32,
        subject_asid: 0,
        subject_measurement: [0u8; 32],
        boot_session_nonce: boot_nonce,
        revocation_epoch: 0,
        delegation_depth: 0,
    };
    sign_token(&mut tok)?;
    Ok(tok)
}

pub fn create_secure_token(
    owner: u64,
    caps: &[Capability],
    ttl_ms: Option<u64>,
) -> Result<CapabilityToken, &'static str> {
    let nonce_bytes = secure_nonce_128();
    let nonce = u64::from_le_bytes([
        nonce_bytes[0],
        nonce_bytes[1],
        nonce_bytes[2],
        nonce_bytes[3],
        nonce_bytes[4],
        nonce_bytes[5],
        nonce_bytes[6],
        nonce_bytes[7],
    ]);
    create_token_with_nonce(owner, caps, ttl_ms, nonce)
}
