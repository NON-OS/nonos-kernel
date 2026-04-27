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

pub const DEVELOPER_SHARE: u64 = 68;
pub const NFT_HOLDERS_SHARE: u64 = 30;
pub const TREASURY_SHARE: u64 = 2;
pub const SHARE_DENOMINATOR: u64 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevenueError {
    NotFound,
    NetworkError,
    InvalidAmount,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RevenueEntry {
    pub capsule_id: [u8; 32],
    pub total_revenue: u128,
    pub developer_paid: u128,
    pub nft_pool_paid: u128,
    pub treasury_paid: u128,
    pub last_distribution: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RevenueSplit {
    pub developer: u128,
    pub nft_pool: u128,
    pub treasury: u128,
}

impl RevenueSplit {
    pub fn calculate(amount: u128) -> Self {
        let dev = (amount * DEVELOPER_SHARE as u128) / SHARE_DENOMINATOR as u128;
        let nft = (amount * NFT_HOLDERS_SHARE as u128) / SHARE_DENOMINATOR as u128;
        let treasury = amount - dev - nft;
        Self { developer: dev, nft_pool: nft, treasury }
    }

    pub fn total(&self) -> u128 {
        self.developer + self.nft_pool + self.treasury
    }
}

impl RevenueEntry {
    pub fn new(capsule_id: [u8; 32]) -> Self {
        Self { capsule_id, ..Default::default() }
    }
    pub fn pending(&self) -> u128 {
        self.total_revenue - self.developer_paid - self.nft_pool_paid - self.treasury_paid
    }
}
