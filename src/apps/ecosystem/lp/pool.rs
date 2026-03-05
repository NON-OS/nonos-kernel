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

//! LP pool calculations.

extern crate alloc;

use alloc::string::String;

const BASIS_POINTS: u128 = 10000;

/// Fast square root using Newton-Raphson method
fn fast_sqrt(x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    let mut guess = x;
    for _ in 0..20 {
        guess = 0.5 * (guess + x / guess);
    }
    guess
}

#[derive(Debug, Clone)]
pub struct PoolInfo {
    pub address: String,
    pub token0_symbol: String,
    pub token1_symbol: String,
    pub token0_address: String,
    pub token1_address: String,
    pub token0_reserve: u128,
    pub token1_reserve: u128,
    pub total_supply: u128,
    pub fee_basis_points: u16,
    pub apy_basis_points: u64,
}

impl PoolInfo {
    pub fn name(&self) -> String {
        alloc::format!("{}/{}", self.token0_symbol, self.token1_symbol)
    }

    pub fn total_value_locked(&self) -> u128 {
        self.token0_reserve.saturating_add(self.token1_reserve)
    }

    pub fn price_token0_in_token1(&self) -> f64 {
        if self.token0_reserve == 0 {
            return 0.0;
        }
        self.token1_reserve as f64 / self.token0_reserve as f64
    }

    pub fn price_token1_in_token0(&self) -> f64 {
        if self.token1_reserve == 0 {
            return 0.0;
        }
        self.token0_reserve as f64 / self.token1_reserve as f64
    }

    pub fn fee_percentage(&self) -> f64 {
        self.fee_basis_points as f64 / 100.0
    }

    pub fn apy_percentage(&self) -> f64 {
        self.apy_basis_points as f64 / 100.0
    }

    pub fn token0_reserve_formatted(&self) -> String {
        format_amount(self.token0_reserve, 18)
    }

    pub fn token1_reserve_formatted(&self) -> String {
        format_amount(self.token1_reserve, 18)
    }
}

#[derive(Debug, Clone)]
pub struct SwapQuote {
    pub amount_in: u128,
    pub amount_out: u128,
    pub price_impact: f64,
    pub fee: u128,
    pub minimum_received: u128,
}

#[derive(Debug, Clone)]
pub struct LiquidityQuote {
    pub token0_amount: u128,
    pub token1_amount: u128,
    pub lp_tokens_minted: u128,
    pub share_of_pool: f64,
}

pub fn calculate_lp_share(lp_tokens: u128, total_supply: u128) -> f64 {
    if total_supply == 0 {
        return 0.0;
    }
    (lp_tokens as f64 / total_supply as f64) * 100.0
}

pub fn estimate_output(
    amount_in: u128,
    reserve_in: u128,
    reserve_out: u128,
    fee_basis_points: u16,
) -> SwapQuote {
    if amount_in == 0 || reserve_in == 0 || reserve_out == 0 {
        return SwapQuote {
            amount_in,
            amount_out: 0,
            price_impact: 0.0,
            fee: 0,
            minimum_received: 0,
        };
    }

    let fee = (amount_in * fee_basis_points as u128) / BASIS_POINTS;
    let amount_in_with_fee = amount_in.saturating_sub(fee);

    let numerator = amount_in_with_fee.saturating_mul(reserve_out);
    let denominator = reserve_in.saturating_add(amount_in_with_fee);
    let amount_out = numerator / denominator;

    let spot_price = reserve_out as f64 / reserve_in as f64;
    let execution_price = if amount_in_with_fee > 0 {
        amount_out as f64 / amount_in_with_fee as f64
    } else {
        0.0
    };
    let price_impact = if spot_price > 0.0 {
        ((spot_price - execution_price) / spot_price) * 100.0
    } else {
        0.0
    };

    let slippage_tolerance = 50;
    let minimum_received =
        (amount_out * (BASIS_POINTS - slippage_tolerance as u128)) / BASIS_POINTS;

    SwapQuote {
        amount_in,
        amount_out,
        price_impact,
        fee,
        minimum_received,
    }
}

pub fn estimate_input(
    amount_out: u128,
    reserve_in: u128,
    reserve_out: u128,
    fee_basis_points: u16,
) -> SwapQuote {
    if amount_out == 0 || reserve_in == 0 || reserve_out == 0 || amount_out >= reserve_out {
        return SwapQuote {
            amount_in: 0,
            amount_out,
            price_impact: 0.0,
            fee: 0,
            minimum_received: amount_out,
        };
    }

    let numerator = reserve_in.saturating_mul(amount_out);
    let denominator = reserve_out.saturating_sub(amount_out);
    let amount_in_before_fee = numerator / denominator + 1;

    let amount_in =
        (amount_in_before_fee * BASIS_POINTS) / (BASIS_POINTS - fee_basis_points as u128);
    let fee = amount_in.saturating_sub(amount_in_before_fee);

    let spot_price = reserve_out as f64 / reserve_in as f64;
    let execution_price = if amount_in > 0 {
        amount_out as f64 / amount_in as f64
    } else {
        0.0
    };
    let price_impact = if spot_price > 0.0 {
        ((spot_price - execution_price) / spot_price) * 100.0
    } else {
        0.0
    };

    SwapQuote {
        amount_in,
        amount_out,
        price_impact,
        fee,
        minimum_received: amount_out,
    }
}

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

pub fn calculate_optimal_token1_amount(
    token0_amount: u128,
    reserve0: u128,
    reserve1: u128,
) -> u128 {
    if reserve0 == 0 {
        return 0;
    }
    (token0_amount * reserve1) / reserve0
}

pub fn calculate_optimal_token0_amount(
    token1_amount: u128,
    reserve0: u128,
    reserve1: u128,
) -> u128 {
    if reserve1 == 0 {
        return 0;
    }
    (token1_amount * reserve0) / reserve1
}

pub fn calculate_impermanent_loss(initial_price_ratio: f64, current_price_ratio: f64) -> f64 {
    if initial_price_ratio <= 0.0 || current_price_ratio <= 0.0 {
        return 0.0;
    }

    let price_change = current_price_ratio / initial_price_ratio;
    let sqrt_price_change = fast_sqrt(price_change);

    let hold_value = (1.0 + price_change) / 2.0;
    let lp_value = sqrt_price_change;

    if hold_value <= 0.0 {
        return 0.0;
    }

    ((lp_value / hold_value) - 1.0) * 100.0
}

fn integer_sqrt(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }

    let mut x = n;
    let mut y = (x + 1) / 2;

    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }

    x
}

fn format_amount(amount: u128, decimals: u8) -> String {
    let divisor = 10u128.pow(decimals as u32);
    let whole = amount / divisor;
    let fraction = amount % divisor;

    let fraction_str = alloc::format!("{:0>width$}", fraction, width = decimals as usize);
    let trimmed = fraction_str.trim_end_matches('0');

    if trimmed.is_empty() {
        alloc::format!("{}", whole)
    } else if trimmed.len() > 4 {
        alloc::format!("{}.{}", whole, &trimmed[..4])
    } else {
        alloc::format!("{}.{}", whole, trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estimate_output() {
        let reserve_in = 1000_000_000_000_000_000_000u128;
        let reserve_out = 1000_000_000_000_000_000_000u128;
        let amount_in = 10_000_000_000_000_000_000u128;

        let quote = estimate_output(amount_in, reserve_in, reserve_out, 30);

        assert!(quote.amount_out > 0);
        assert!(quote.amount_out < amount_in);
        assert!(quote.fee > 0);
        assert!(quote.price_impact > 0.0);
    }

    #[test]
    fn test_calculate_liquidity() {
        let token0 = 1000_000_000_000_000_000_000u128;
        let token1 = 1000_000_000_000_000_000_000u128;

        let quote = calculate_liquidity_tokens(token0, token1, 0, 0, 0);

        assert!(quote.lp_tokens_minted > 0);
        assert_eq!(quote.share_of_pool, 100.0);
    }

    #[test]
    fn test_impermanent_loss() {
        let loss = calculate_impermanent_loss(1.0, 2.0);
        assert!(loss < 0.0);
        assert!(loss > -10.0);

        let no_loss = calculate_impermanent_loss(1.0, 1.0);
        assert!((no_loss - 0.0).abs() < 0.001);
    }
}
