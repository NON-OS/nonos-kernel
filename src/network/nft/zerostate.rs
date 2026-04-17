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
use super::types::{NftError, NftInfo};

pub const ZEROSTATE_ADDR: [u8; 20] = [
    0x7b, 0x57, 0x5D, 0xD8, 0xe8, 0xb1, 0x11, 0xc5, 0x2A, 0xb1,
    0xe8, 0x72, 0x92, 0x4d, 0x4E, 0xfd, 0x4D, 0xF4, 0x03, 0xdf,
];

pub fn balance_of(owner: &[u8; 20]) -> Result<u64, NftError> {
    let mut calldata = abi::selector("balanceOf(address)").to_vec();
    calldata.extend_from_slice(&[0u8; 12]);
    calldata.extend_from_slice(owner);
    let result = eth::client::call(&ZEROSTATE_ADDR, &calldata).map_err(|_| NftError::NetworkError)?;
    if result.len() < 32 { return Err(NftError::InvalidToken); }
    let bytes: [u8; 8] = result[24..32].try_into().map_err(|_| NftError::InvalidToken)?;
    Ok(u64::from_be_bytes(bytes))
}

pub fn owner_of(token_id: u64) -> Result<[u8; 20], NftError> {
    let mut calldata = abi::selector("ownerOf(uint256)").to_vec();
    calldata.extend_from_slice(&[0u8; 24]);
    calldata.extend_from_slice(&token_id.to_be_bytes());
    let result = eth::client::call(&ZEROSTATE_ADDR, &calldata).map_err(|_| NftError::NetworkError)?;
    if result.len() < 32 { return Err(NftError::InvalidToken); }
    let mut owner = [0u8; 20];
    owner.copy_from_slice(&result[12..32]);
    Ok(owner)
}

pub fn get_token_info(token_id: u64) -> Result<NftInfo, NftError> {
    let owner = owner_of(token_id)?;
    let mut calldata = abi::selector("tokenTier(uint256)").to_vec();
    calldata.extend_from_slice(&[0u8; 24]);
    calldata.extend_from_slice(&token_id.to_be_bytes());
    let result = eth::client::call(&ZEROSTATE_ADDR, &calldata).map_err(|_| NftError::NetworkError)?;
    let tier = if result.len() >= 32 { result[31] } else { 0 };
    Ok(NftInfo { token_id, owner, tier, minted_at: 0 })
}

pub fn is_holder(addr: &[u8; 20]) -> Result<bool, NftError> { Ok(balance_of(addr)? > 0) }

pub fn total_supply() -> Result<u64, NftError> {
    let calldata = abi::selector("totalSupply()").to_vec();
    let result = eth::client::call(&ZEROSTATE_ADDR, &calldata).map_err(|_| NftError::NetworkError)?;
    if result.len() < 32 { return Err(NftError::InvalidToken); }
    let bytes: [u8; 8] = result[24..32].try_into().map_err(|_| NftError::InvalidToken)?;
    Ok(u64::from_be_bytes(bytes))
}
