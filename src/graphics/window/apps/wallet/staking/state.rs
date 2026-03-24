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

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use spin::Mutex;

pub struct StakingState {
    pub staked_amount: u128,
    pub weighted_amount: u128,
    pub boost: u32,
    pub pending_rewards: u128,
    pub total_pool_staked: u128,
    pub total_weighted: u128,
    pub current_apy: u32,
    pub current_epoch: u32,
    pub nft_count: u8,
    pub genesis_started: bool,
}

impl StakingState {
    pub const fn new() -> Self {
        Self { staked_amount: 0, weighted_amount: 0, boost: 10000, pending_rewards: 0, total_pool_staked: 0, total_weighted: 0, current_apy: 0, current_epoch: 0, nft_count: 0, genesis_started: false }
    }
    pub fn boost_display(&self) -> &'static [u8] { match self.nft_count { 0 => b"1.0x", 1 => b"1.5x", 2 => b"2.0x", _ => b"2.5x" } }
}

pub static STAKING_STATE: Mutex<StakingState> = Mutex::new(StakingState::new());
pub static STAKE_INPUT: Mutex<[u8; 32]> = Mutex::new([0u8; 32]);
pub static STAKE_INPUT_LEN: AtomicU8 = AtomicU8::new(0);
pub static STAKE_MODE: AtomicU8 = AtomicU8::new(0);
pub static STAKE_REFRESHING: AtomicBool = AtomicBool::new(false);

pub fn refresh_staking_data() {
    if STAKE_REFRESHING.swap(true, Ordering::SeqCst) { return; }
    if let Err(_) = super::rpc::fetch_staking_state() { crate::graphics::window::apps::wallet::state::set_status(b"Staking fetch failed", false); }
    STAKE_REFRESHING.store(false, Ordering::SeqCst);
}

pub fn clear_stake_input() { for b in STAKE_INPUT.lock().iter_mut() { *b = 0; } STAKE_INPUT_LEN.store(0, Ordering::SeqCst); }
