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

use super::helpers::parse_address;
use alloc::string::String;

pub(super) const ADD_LIQUIDITY_SELECTOR: [u8; 4] = [0xe8, 0xe3, 0x37, 0x00];
pub(super) const REMOVE_LIQUIDITY_SELECTOR: [u8; 4] = [0x02, 0x75, 0x1c, 0xec];
pub(super) const CLAIM_REWARDS_SELECTOR: [u8; 4] = [0x4e, 0x71, 0xd9, 0x2d];
pub(super) const COMPOUND_SELECTOR: [u8; 4] = [0xf6, 0x9e, 0x20, 0x46];
pub(super) const GET_POSITION_SELECTOR: [u8; 4] = [0x99, 0xfb, 0xab, 0x88];
pub(super) const GET_RESERVES_SELECTOR: [u8; 4] = [0x09, 0x02, 0xf1, 0xac];
pub(super) const TOTAL_SUPPLY_SELECTOR: [u8; 4] = [0x18, 0x16, 0x0d, 0xdd];
pub(super) const BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];
pub(super) const PENDING_REWARDS_SELECTOR: [u8; 4] = [0xf4, 0x0f, 0x0f, 0x52];

#[derive(Debug, Clone)]
pub struct LpContract {
    pub(super) address: [u8; 20],
    pub(super) address_hex: String,
}

impl LpContract {
    pub fn new(address: &str) -> Self {
        let address_bytes = parse_address(address).unwrap_or([0u8; 20]);
        Self { address: address_bytes, address_hex: String::from(address) }
    }

    pub fn address(&self) -> &[u8; 20] {
        &self.address
    }

    pub fn address_hex(&self) -> &str {
        &self.address_hex
    }
}
