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

use alloc::string::String;

pub(super) const BASIS_POINTS: u128 = 10000;

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

pub fn calculate_lp_share(lp_tokens: u128, total_supply: u128) -> f64 {
    if total_supply == 0 {
        return 0.0;
    }
    (lp_tokens as f64 / total_supply as f64) * 100.0
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

pub(super) fn integer_sqrt(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = x / 2 + 1;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

pub(super) fn format_amount(amount: u128, decimals: u8) -> String {
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
