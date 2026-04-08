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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftError { NotFound, NotOwner, NetworkError, InvalidToken, AlreadyClaimed }

#[derive(Debug, Clone, Copy, Default)]
pub struct NftInfo {
    pub token_id: u64,
    pub owner: [u8; 20],
    pub tier: u8,
    pub minted_at: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RewardInfo {
    pub claimable: u128,
    pub claimed: u128,
    pub last_claim: u64,
    pub epoch: u64,
}

pub const TIER_STANDARD: u8 = 0;
pub const TIER_GOLD: u8 = 1;
pub const TIER_DIAMOND: u8 = 2;

impl NftInfo {
    pub fn tier_multiplier(&self) -> u64 {
        match self.tier {
            TIER_DIAMOND => 3,
            TIER_GOLD => 2,
            _ => 1,
        }
    }
}

impl RewardInfo {
    pub fn total_earned(&self) -> u128 { self.claimable + self.claimed }
}
