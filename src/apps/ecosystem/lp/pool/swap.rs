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

use super::helpers::BASIS_POINTS;
use super::types::SwapQuote;

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
    let execution_price =
        if amount_in_with_fee > 0 { amount_out as f64 / amount_in_with_fee as f64 } else { 0.0 };
    let price_impact =
        if spot_price > 0.0 { ((spot_price - execution_price) / spot_price) * 100.0 } else { 0.0 };
    let slippage_tolerance = 50;
    let minimum_received =
        (amount_out * (BASIS_POINTS - slippage_tolerance as u128)) / BASIS_POINTS;
    SwapQuote { amount_in, amount_out, price_impact, fee, minimum_received }
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
    let execution_price = if amount_in > 0 { amount_out as f64 / amount_in as f64 } else { 0.0 };
    let price_impact =
        if spot_price > 0.0 { ((spot_price - execution_price) / spot_price) * 100.0 } else { 0.0 };
    SwapQuote { amount_in, amount_out, price_impact, fee, minimum_received: amount_out }
}
