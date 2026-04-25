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

use super::helpers::{calculate_lp_share, integer_sqrt};
use super::types::LiquidityQuote;

pub fn calculate_liquidity_tokens(
    token0_amount: u128,
    token1_amount: u128,
    reserve0: u128,
    reserve1: u128,
    total_supply: u128,
) -> LiquidityQuote {
    if total_supply == 0 {
        let liquidity = integer_sqrt(token0_amount.saturating_mul(token1_amount));
        let minimum_liquidity = 1000u128;
        let lp_tokens = liquidity.saturating_sub(minimum_liquidity);
        return LiquidityQuote {
            token0_amount,
            token1_amount,
            lp_tokens_minted: lp_tokens,
            share_of_pool: 100.0,
        };
    }
    let liquidity0 = (token0_amount * total_supply) / reserve0;
    let liquidity1 = (token1_amount * total_supply) / reserve1;
    let lp_tokens = liquidity0.min(liquidity1);
    let new_total_supply = total_supply.saturating_add(lp_tokens);
    let share = calculate_lp_share(lp_tokens, new_total_supply);
    LiquidityQuote {
        token0_amount,
        token1_amount,
        lp_tokens_minted: lp_tokens,
        share_of_pool: share,
    }
}

pub fn calculate_remove_liquidity(
    lp_tokens: u128,
    reserve0: u128,
    reserve1: u128,
    total_supply: u128,
) -> (u128, u128) {
    if total_supply == 0 {
        return (0, 0);
    }
    let amount0 = (lp_tokens * reserve0) / total_supply;
    let amount1 = (lp_tokens * reserve1) / total_supply;
    (amount0, amount1)
}
