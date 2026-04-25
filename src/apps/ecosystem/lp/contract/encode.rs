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
use super::types::*;
use alloc::vec::Vec;

impl LpContract {
    pub fn encode_add_liquidity(
        &self,
        token0_amount: u128,
        token1_amount: u128,
        min_liquidity: u128,
        deadline: u64,
    ) -> Vec<u8> {
        let mut data = ADD_LIQUIDITY_SELECTOR.to_vec();
        data.extend_from_slice(&encode_u256(token0_amount));
        data.extend_from_slice(&encode_u256(token1_amount));
        data.extend_from_slice(&encode_u256(min_liquidity));
        data.extend_from_slice(&encode_u256(deadline as u128));
        data
    }

    pub fn encode_remove_liquidity(
        &self,
        lp_amount: u128,
        min_token0: u128,
        min_token1: u128,
        deadline: u64,
    ) -> Vec<u8> {
        let mut data = REMOVE_LIQUIDITY_SELECTOR.to_vec();
        data.extend_from_slice(&encode_u256(lp_amount));
        data.extend_from_slice(&encode_u256(min_token0));
        data.extend_from_slice(&encode_u256(min_token1));
        data.extend_from_slice(&encode_u256(deadline as u128));
        data
    }

    pub fn encode_claim_rewards(&self) -> Vec<u8> {
        CLAIM_REWARDS_SELECTOR.to_vec()
    }

    pub fn encode_compound(&self) -> Vec<u8> {
        COMPOUND_SELECTOR.to_vec()
    }

    pub fn encode_get_position(&self, account: &[u8; 20]) -> Vec<u8> {
        let mut data = GET_POSITION_SELECTOR.to_vec();
        data.extend_from_slice(&encode_address(account));
        data
    }

    pub fn encode_get_reserves(&self) -> Vec<u8> {
        GET_RESERVES_SELECTOR.to_vec()
    }

    pub fn encode_total_supply(&self) -> Vec<u8> {
        TOTAL_SUPPLY_SELECTOR.to_vec()
    }

    pub fn encode_balance_of(&self, account: &[u8; 20]) -> Vec<u8> {
        let mut data = BALANCE_OF_SELECTOR.to_vec();
        data.extend_from_slice(&encode_address(account));
        data
    }

    pub fn encode_pending_rewards(&self, account: &[u8; 20]) -> Vec<u8> {
        let mut data = PENDING_REWARDS_SELECTOR.to_vec();
        data.extend_from_slice(&encode_address(account));
        data
    }
}
