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

//! NONOS Ecosystem Staking Module.

extern crate alloc;

pub mod contract;
pub mod rewards;
pub mod state;

pub use contract::{
    claim_rewards, get_pending_rewards, get_staked_amount, stake, unstake, StakingContract,
};
pub use rewards::{calculate_apy, estimate_rewards, RewardsInfo};
pub use state::{get_staking_state, init, StakingState};

use alloc::string::String;
use core::sync::atomic::{AtomicBool, Ordering};

static RUNNING: AtomicBool = AtomicBool::new(false);

pub fn start() {
    RUNNING.store(true, Ordering::SeqCst);
}

pub fn stop() {
    RUNNING.store(false, Ordering::SeqCst);
}

pub fn is_running() -> bool {
    RUNNING.load(Ordering::Relaxed)
}

pub fn claim_pending_rewards() -> Result<String, &'static str> {
    let state = get_staking_state().ok_or("Staking not initialized")?;
    let pending = state.pending_rewards;

    if pending == 0 {
        return Err("No rewards to claim");
    }

    let amount_str = format_amount(pending);
    Ok(amount_str)
}

fn format_amount(amount: u128) -> String {
    let eth = amount / 1_000_000_000_000_000_000;
    let decimals = (amount % 1_000_000_000_000_000_000) / 10_000_000_000_000_000;
    alloc::format!("{}.{:02}", eth, decimals)
}

pub fn stake_simple(amount: u64) -> Result<(), &'static str> {
    let state = get_staking_state().ok_or("Staking not initialized")?;
    let amount_wei = (amount as u128) * 1_000_000_000_000_000_000;
    state::update_staked_amount(state.staked_amount.saturating_add(amount_wei));
    Ok(())
}

pub fn unstake_simple(amount: u64) -> Result<(), &'static str> {
    let state = get_staking_state().ok_or("Staking not initialized")?;
    let amount_wei = (amount as u128) * 1_000_000_000_000_000_000;
    if state.staked_amount < amount_wei {
        return Err("Insufficient staked balance");
    }
    state::update_staked_amount(state.staked_amount.saturating_sub(amount_wei));
    Ok(())
}
