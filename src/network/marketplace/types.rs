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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarketError { NotFound, NetworkError, InvalidResponse, InsufficientFunds, Unauthorized }

#[derive(Debug, Clone)]
pub struct CapsuleListing {
    pub id: [u8; 32],
    pub developer: [u8; 20],
    pub ipfs_cid: String,
    pub manifest_hash: [u8; 32],
    pub price: u128,
    pub caps_required: u64,
    pub active: bool,
    pub total_unlocks: u64,
}

#[derive(Debug, Clone)]
pub struct UnlockInfo {
    pub user: [u8; 20],
    pub capsule_id: [u8; 32],
    pub unlocked_at: u64,
    pub expires_at: u64,
    pub caps_granted: u64,
}

impl CapsuleListing {
    pub fn price_wei(&self) -> u128 { self.price }
    pub fn price_nox(&self) -> u128 { self.price / 1_000_000_000_000_000_000 }
}

impl UnlockInfo {
    pub fn is_expired(&self, now: u64) -> bool { now >= self.expires_at }
    pub fn remaining(&self, now: u64) -> u64 { self.expires_at.saturating_sub(now) }
}
