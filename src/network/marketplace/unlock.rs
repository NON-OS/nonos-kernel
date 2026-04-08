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

use crate::network::eth::{self, abi};
use super::types::{MarketError, UnlockInfo};
use super::registry::REGISTRY_ADDR;

pub fn unlock_capsule(capsule_id: &[u8; 32], caps: u64, value: u128) -> Result<UnlockInfo, MarketError> {
    let mut calldata = abi::selector("unlockCapsule(bytes32,uint64)").to_vec();
    calldata.extend_from_slice(capsule_id);
    calldata.extend_from_slice(&[0u8; 24]);
    calldata.extend_from_slice(&caps.to_be_bytes());
    let result = eth::client::send_tx(&REGISTRY_ADDR, &calldata, value).map_err(|_| MarketError::NetworkError)?;
    decode_unlock_info(&result, capsule_id)
}

pub fn check_unlock(user: &[u8; 20], capsule_id: &[u8; 32]) -> Result<UnlockInfo, MarketError> {
    let mut calldata = abi::selector("unlocks(address,bytes32)").to_vec();
    calldata.extend_from_slice(&[0u8; 12]);
    calldata.extend_from_slice(user);
    calldata.extend_from_slice(capsule_id);
    let result = eth::client::call(&REGISTRY_ADDR, &calldata).map_err(|_| MarketError::NetworkError)?;
    decode_unlock_result(user, capsule_id, &result)
}

pub fn has_valid_unlock(user: &[u8; 20], capsule_id: &[u8; 32]) -> Result<bool, MarketError> {
    let info = check_unlock(user, capsule_id)?;
    let now = crate::time::unix_timestamp();
    Ok(!info.is_expired(now))
}

fn decode_unlock_info(data: &[u8], capsule_id: &[u8; 32]) -> Result<UnlockInfo, MarketError> {
    if data.len() < 64 { return Err(MarketError::InvalidResponse); }
    let unlocked_at = u64::from_be_bytes(data[24..32].try_into().unwrap());
    let expires_at = u64::from_be_bytes(data[56..64].try_into().unwrap());
    let caps_granted = u64::from_be_bytes(data[88..96].try_into().ok().unwrap_or([0u8; 8]));
    Ok(UnlockInfo { user: [0u8; 20], capsule_id: *capsule_id, unlocked_at, expires_at, caps_granted })
}

fn decode_unlock_result(user: &[u8; 20], capsule_id: &[u8; 32], data: &[u8]) -> Result<UnlockInfo, MarketError> {
    let mut info = decode_unlock_info(data, capsule_id)?;
    info.user = *user;
    Ok(info)
}
