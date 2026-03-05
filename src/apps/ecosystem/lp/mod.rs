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

mod api;
pub mod contract;
mod ops;
pub mod pool;
pub mod state;

pub use api::{start, stop, is_running};
pub use contract::{
    add_liquidity, claim_lp_rewards, compound_rewards, get_lp_position, remove_liquidity,
    LpContract,
};
pub use ops::auto_compound;
pub use pool::{calculate_lp_share, estimate_output, PoolInfo};
pub use state::{get_lp_state, init, is_initialized, LpState};
