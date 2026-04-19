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

//! NONOS Ecosystem Liquidity Provider Module.

extern crate alloc;

pub mod contract;
mod ops;
pub mod pool;
pub mod state;

pub use contract::{
    add_liquidity, claim_lp_rewards, compound_rewards, get_lp_position, remove_liquidity,
    LpContract,
};
pub use ops::auto_compound;
pub use pool::{calculate_lp_share, estimate_output, PoolInfo};
pub use state::{get_lp_state, init, is_initialized, LpState};

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

pub fn add_liquidity_simple(token_a: u64, token_b: u64) -> Result<u64, &'static str> {
    let _state = get_lp_state().ok_or("LP not initialized")?;
    let lp_tokens = ((token_a as u128) * (token_b as u128)).isqrt() as u64;
    Ok(lp_tokens)
}

pub fn remove_liquidity_simple(lp_amount: u64) -> Result<(u64, u64), &'static str> {
    let _state = get_lp_state().ok_or("LP not initialized")?;
    let half = lp_amount / 2;
    Ok((half, half))
}
