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
use super::helpers::{encode_address, encode_u256};
use super::types::StakingContract;
use alloc::vec::Vec;

const STAKE_SELECTOR: [u8; 4] = [0xa6, 0x94, 0xfc, 0x3a];
const UNSTAKE_SELECTOR: [u8; 4] = [0x2e, 0x17, 0xde, 0x78];
const CLAIM_SELECTOR: [u8; 4] = [0x4e, 0x71, 0xd9, 0x2d];
pub(super) const STAKED_AMOUNT_SELECTOR: [u8; 4] = [0x37, 0x3d, 0x6b, 0x32];
pub(super) const PENDING_REWARDS_SELECTOR: [u8; 4] = [0xf4, 0x0f, 0x0f, 0x52];
pub(super) const TOTAL_STAKED_SELECTOR: [u8; 4] = [0x81, 0x7b, 0x1c, 0xd2];
pub(super) const APY_SELECTOR: [u8; 4] = [0x2d, 0x33, 0x9a, 0x5f];
const APPROVE_SELECTOR: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];

impl StakingContract {
    pub fn encode_stake(&self, amount: u128) -> Vec<u8> {
        let mut data = STAKE_SELECTOR.to_vec();
        data.extend_from_slice(&encode_u256(amount));
        data
    }
    pub fn encode_unstake(&self, amount: u128) -> Vec<u8> {
        let mut data = UNSTAKE_SELECTOR.to_vec();
        data.extend_from_slice(&encode_u256(amount));
        data
    }
    pub fn encode_claim(&self) -> Vec<u8> {
        CLAIM_SELECTOR.to_vec()
    }
    pub fn encode_staked_amount(&self, account: &[u8; 20]) -> Vec<u8> {
        let mut data = STAKED_AMOUNT_SELECTOR.to_vec();
        data.extend_from_slice(&encode_address(account));
        data
    }
    pub fn encode_pending_rewards(&self, account: &[u8; 20]) -> Vec<u8> {
        let mut data = PENDING_REWARDS_SELECTOR.to_vec();
        data.extend_from_slice(&encode_address(account));
        data
    }
    pub fn encode_total_staked(&self) -> Vec<u8> {
        TOTAL_STAKED_SELECTOR.to_vec()
    }
    pub fn encode_apy(&self) -> Vec<u8> {
        APY_SELECTOR.to_vec()
    }
    pub fn encode_approve(&self, amount: u128) -> Vec<u8> {
        let mut data = APPROVE_SELECTOR.to_vec();
        data.extend_from_slice(&encode_address(&self.staking_address));
        data.extend_from_slice(&encode_u256(amount));
        data
    }
}
