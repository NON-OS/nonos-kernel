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

extern crate alloc;
use super::types::{UnlockError, UnlockRequest, UnlockResponse};
use crate::network::eth::{self, abi};
use alloc::vec::Vec;

const REGISTRY_ADDR: [u8; 20] = [
    0xB4, 0x7F, 0xBd, 0x4E, 0x66, 0x8f, 0xaD, 0x29, 0xC3, 0x74, 0x52, 0x3B, 0x1f, 0x7F, 0x82, 0xEA,
    0x8b, 0xa1, 0x78, 0xD7,
];

pub fn request_unlock(req: &UnlockRequest) -> Result<UnlockResponse, UnlockError> {
    let calldata = encode_unlock_call(req);
    let result =
        eth::client::call(&REGISTRY_ADDR, &calldata).map_err(|_| UnlockError::NetworkError)?;
    decode_unlock_response(&result)
}

fn encode_unlock_call(req: &UnlockRequest) -> Vec<u8> {
    let selector = abi::selector("unlockCapsule(bytes32,uint64)");
    let mut data = selector.to_vec();
    data.extend_from_slice(&req.capsule_id);
    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&req.requested_caps.to_be_bytes());
    data
}

fn decode_unlock_response(data: &[u8]) -> Result<UnlockResponse, UnlockError> {
    if data.len() < 160 {
        return Err(UnlockError::NotFound);
    }
    let mut token = [0u8; 32];
    let mut capsule_id = [0u8; 32];
    let mut manifest_hash = [0u8; 32];
    token.copy_from_slice(&data[0..32]);
    capsule_id.copy_from_slice(&data[32..64]);
    manifest_hash.copy_from_slice(&data[64..96]);
    let mut caps_bytes = [0u8; 8];
    caps_bytes.copy_from_slice(&data[120..128]);
    let approved_caps = u64::from_be_bytes(caps_bytes);
    let mut expires_bytes = [0u8; 8];
    expires_bytes.copy_from_slice(&data[152..160]);
    let expires_at = u64::from_be_bytes(expires_bytes);
    Ok(UnlockResponse { token, capsule_id, manifest_hash, approved_caps, expires_at })
}

pub fn verify_token(response: &UnlockResponse, now: u64) -> Result<(), UnlockError> {
    if response.is_expired(now) {
        return Err(UnlockError::Expired);
    }
    Ok(())
}
