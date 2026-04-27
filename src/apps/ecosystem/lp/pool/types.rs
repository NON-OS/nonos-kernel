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

use super::helpers::format_amount;
use alloc::string::String;

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
            0.0
        } else {
            self.token1_reserve as f64 / self.token0_reserve as f64
        }
    }
    pub fn price_token1_in_token0(&self) -> f64 {
        if self.token1_reserve == 0 {
            0.0
        } else {
            self.token0_reserve as f64 / self.token1_reserve as f64
        }
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
