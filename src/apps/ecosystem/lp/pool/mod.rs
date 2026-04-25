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

mod helpers;
mod liquidity;
mod optimal;
mod swap;
mod types;

pub use helpers::{calculate_impermanent_loss, calculate_lp_share};
pub use liquidity::{calculate_liquidity_tokens, calculate_remove_liquidity};
pub use optimal::{calculate_optimal_token0_amount, calculate_optimal_token1_amount};
pub use swap::{estimate_input, estimate_output};
pub use types::{LiquidityQuote, PoolInfo, SwapQuote};
