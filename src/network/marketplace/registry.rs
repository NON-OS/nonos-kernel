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
use alloc::vec::Vec;
use crate::network::eth::{self, abi};
use super::types::{MarketError, CapsuleListing};

pub const REGISTRY_ADDR: [u8; 20] = [0x00; 20];

pub fn register_capsule(ipfs_cid: &str, manifest_hash: &[u8; 32], price: u128, caps: u64) -> Result<[u8; 32], MarketError> {
    let calldata = encode_register(ipfs_cid, manifest_hash, price, caps);
    let result = eth::client::send_tx(&REGISTRY_ADDR, &calldata, 0).map_err(|_| MarketError::NetworkError)?;
    if result.len() < 32 { return Err(MarketError::InvalidResponse); }
    let mut id = [0u8; 32];
    id.copy_from_slice(&result[0..32]);
    Ok(id)
}

pub fn update_price(capsule_id: &[u8; 32], new_price: u128) -> Result<(), MarketError> {
    let mut calldata = abi::selector("updatePrice(bytes32,uint256)").to_vec();
    calldata.extend_from_slice(capsule_id);
    calldata.extend_from_slice(&[0u8; 16]);
    calldata.extend_from_slice(&new_price.to_be_bytes());
    eth::client::send_tx(&REGISTRY_ADDR, &calldata, 0).map_err(|_| MarketError::NetworkError)?;
    Ok(())
}

pub fn deactivate(capsule_id: &[u8; 32]) -> Result<(), MarketError> {
    let mut calldata = abi::selector("deactivateCapsule(bytes32)").to_vec();
    calldata.extend_from_slice(capsule_id);
    eth::client::send_tx(&REGISTRY_ADDR, &calldata, 0).map_err(|_| MarketError::NetworkError)?;
    Ok(())
}

fn encode_register(ipfs_cid: &str, manifest_hash: &[u8; 32], price: u128, caps: u64) -> Vec<u8> {
    let mut data = abi::selector("registerCapsule(string,bytes32,uint256,uint64)").to_vec();
    data.extend_from_slice(&[0u8; 32]);
    data.extend_from_slice(manifest_hash);
    data.extend_from_slice(&[0u8; 16]);
    data.extend_from_slice(&price.to_be_bytes());
    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&caps.to_be_bytes());
    data.extend_from_slice(&(ipfs_cid.len() as u64).to_be_bytes());
    data.extend_from_slice(ipfs_cid.as_bytes());
    data
}
