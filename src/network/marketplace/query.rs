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
use alloc::string::String;
use crate::network::eth::{self, abi};
use super::types::{MarketError, CapsuleListing};
use super::registry::REGISTRY_ADDR;

pub fn get_listing(capsule_id: &[u8; 32]) -> Result<CapsuleListing, MarketError> {
    let mut calldata = abi::selector("capsules(bytes32)").to_vec();
    calldata.extend_from_slice(capsule_id);
    let result = eth::client::call(&REGISTRY_ADDR, &calldata).map_err(|_| MarketError::NetworkError)?;
    decode_listing(capsule_id, &result)
}

pub fn get_total_unlocks(capsule_id: &[u8; 32]) -> Result<u64, MarketError> {
    let listing = get_listing(capsule_id)?;
    Ok(listing.total_unlocks)
}

pub fn is_active(capsule_id: &[u8; 32]) -> Result<bool, MarketError> {
    let listing = get_listing(capsule_id)?;
    Ok(listing.active)
}

fn decode_listing(id: &[u8; 32], data: &[u8]) -> Result<CapsuleListing, MarketError> {
    if data.len() < 192 { return Err(MarketError::InvalidResponse); }
    let mut developer = [0u8; 20];
    developer.copy_from_slice(&data[12..32]);
    let mut manifest_hash = [0u8; 32];
    manifest_hash.copy_from_slice(&data[32..64]);
    let price = u128::from_be_bytes(data[80..96].try_into().unwrap());
    let caps_required = u64::from_be_bytes(data[120..128].try_into().unwrap());
    let active = data[159] != 0;
    let total_unlocks = u64::from_be_bytes(data[184..192].try_into().unwrap());
    Ok(CapsuleListing {
        id: *id, developer, ipfs_cid: String::new(), manifest_hash, price, caps_required, active, total_unlocks
    })
}
