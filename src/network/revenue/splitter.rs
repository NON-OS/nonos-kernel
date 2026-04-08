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
use super::{tracker, types::*};

pub const SPLITTER_ADDR: [u8; 20] = [0x00; 20];
pub const REWARD_POOL_ADDR: [u8; 20] = [0x00; 20];

pub fn distribute(capsule_id: &[u8; 32]) -> Result<RevenueSplit, RevenueError> {
    let pending = tracker::get_pending(capsule_id);
    if pending == 0 { return Err(RevenueError::InvalidAmount); }
    let split = RevenueSplit::calculate(pending);
    call_distribute(capsule_id)?;
    tracker::record_distribution(capsule_id, &split);
    Ok(split)
}

pub fn claim_developer(capsule_id: &[u8; 32]) -> Result<u128, RevenueError> {
    let entry = tracker::get_entry(capsule_id).ok_or(RevenueError::NotFound)?;
    let claimable = entry.developer_paid;
    if claimable == 0 { return Err(RevenueError::InvalidAmount); }
    call_claim_developer(capsule_id)?;
    Ok(claimable)
}

pub fn deposit_to_pool(capsule_id: &[u8; 32], amount: u128) -> Result<(), RevenueError> {
    let mut calldata = abi::selector("deposit(bytes32,uint256)").to_vec();
    calldata.extend_from_slice(capsule_id);
    calldata.extend_from_slice(&[0u8; 16]);
    calldata.extend_from_slice(&amount.to_be_bytes());
    eth::client::send_tx(&REWARD_POOL_ADDR, &calldata, 0).map_err(|_| RevenueError::NetworkError)?;
    Ok(())
}

fn call_distribute(capsule_id: &[u8; 32]) -> Result<(), RevenueError> {
    let mut calldata = abi::selector("distribute(bytes32)").to_vec();
    calldata.extend_from_slice(capsule_id);
    eth::client::send_tx(&SPLITTER_ADDR, &calldata, 0).map_err(|_| RevenueError::NetworkError)?;
    Ok(())
}

fn call_claim_developer(capsule_id: &[u8; 32]) -> Result<(), RevenueError> {
    let mut calldata = abi::selector("claimDeveloper(bytes32)").to_vec();
    calldata.extend_from_slice(capsule_id);
    eth::client::send_tx(&SPLITTER_ADDR, &calldata, 0).map_err(|_| RevenueError::NetworkError)?;
    Ok(())
}
