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
use super::types::{NftError, RewardInfo};

pub const REWARD_POOL_ADDR: [u8; 20] = [
    0xF3, 0xA4, 0xbA, 0xc4, 0x62, 0x9A, 0xab, 0x57, 0x47, 0x31,
    0xED, 0xf5, 0xA7, 0x8f, 0x4e, 0xc4, 0xFA, 0x14, 0x20, 0x79,
];

pub fn get_claimable(token_id: u64) -> Result<u128, NftError> {
    let mut calldata = abi::selector("claimable(uint256)").to_vec();
    calldata.extend_from_slice(&[0u8; 24]);
    calldata.extend_from_slice(&token_id.to_be_bytes());
    let result = eth::client::call(&REWARD_POOL_ADDR, &calldata).map_err(|_| NftError::NetworkError)?;
    if result.len() < 32 { return Err(NftError::InvalidToken); }
    let bytes: [u8; 16] = result[16..32].try_into().map_err(|_| NftError::InvalidToken)?;
    Ok(u128::from_be_bytes(bytes))
}

pub fn claim_rewards(token_id: u64, key: &[u8; 32]) -> Result<u128, NftError> {
    let mut calldata = abi::selector("claim(uint256)").to_vec();
    calldata.extend_from_slice(&[0u8; 24]);
    calldata.extend_from_slice(&token_id.to_be_bytes());
    let result = eth::client::send_tx(&REWARD_POOL_ADDR, 0, calldata, key).map_err(|_| NftError::NetworkError)?;
    Ok(u128::from_be_bytes(result[16..32].try_into().unwrap_or([0u8; 16])))
}

pub fn get_reward_info(token_id: u64) -> Result<RewardInfo, NftError> {
    let claimable = get_claimable(token_id)?;
    let mut calldata = abi::selector("claimed(uint256)").to_vec();
    calldata.extend_from_slice(&[0u8; 24]);
    calldata.extend_from_slice(&token_id.to_be_bytes());
    let result = eth::client::call(&REWARD_POOL_ADDR, &calldata).map_err(|_| NftError::NetworkError)?;
    let claimed = result.get(16..32).and_then(|s| s.try_into().ok()).map(u128::from_be_bytes).unwrap_or(0);
    Ok(RewardInfo { claimable, claimed, last_claim: 0, epoch: 0 })
}

pub fn current_epoch() -> Result<u64, NftError> {
    let calldata = abi::selector("currentEpoch()").to_vec();
    let result = eth::client::call(&REWARD_POOL_ADDR, &calldata).map_err(|_| NftError::NetworkError)?;
    Ok(result.get(24..32).and_then(|s| s.try_into().ok()).map(u64::from_be_bytes).unwrap_or(0))
}

pub fn epoch_pool_balance() -> Result<u128, NftError> {
    let calldata = abi::selector("epochPool()").to_vec();
    let result = eth::client::call(&REWARD_POOL_ADDR, &calldata).map_err(|_| NftError::NetworkError)?;
    Ok(result.get(16..32).and_then(|s| s.try_into().ok()).map(u128::from_be_bytes).unwrap_or(0))
}
