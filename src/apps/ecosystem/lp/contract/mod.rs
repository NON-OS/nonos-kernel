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

mod add;
mod encode;
mod helpers;
mod position;
mod query;
mod remove;
mod rewards;
mod types;

pub use add::add_liquidity;
pub use helpers::{decode_u256, encode_address, encode_u256, parse_address};
pub use position::get_lp_position;
pub use query::{get_lp_balance, get_pending_rewards_amount, get_reserves, get_total_supply};
pub use remove::remove_liquidity;
pub use rewards::{claim_lp_rewards, compound_rewards};
pub use types::LpContract;
