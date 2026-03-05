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

//! Staking rewards calculations.

extern crate alloc;

use alloc::string::String;

const SECONDS_PER_YEAR: u64 = 365 * 24 * 60 * 60;
const BASIS_POINTS: u128 = 10000;

#[derive(Debug, Clone)]
pub struct RewardsInfo {
    pub staked_amount: u128,
    pub pending_rewards: u128,
    pub apy_basis_points: u64,
    pub daily_rewards: u128,
    pub weekly_rewards: u128,
    pub monthly_rewards: u128,
    pub yearly_rewards: u128,
}

impl RewardsInfo {
    pub fn daily_rewards_formatted(&self) -> String {
        format_amount(self.daily_rewards)
    }

    pub fn weekly_rewards_formatted(&self) -> String {
        format_amount(self.weekly_rewards)
    }

    pub fn monthly_rewards_formatted(&self) -> String {
        format_amount(self.monthly_rewards)
    }

    pub fn yearly_rewards_formatted(&self) -> String {
        format_amount(self.yearly_rewards)
    }

    pub fn apy_percentage(&self) -> f64 {
        self.apy_basis_points as f64 / 100.0
    }
}

pub fn calculate_apy(total_rewards_per_year: u128, total_staked: u128) -> u64 {
    if total_staked == 0 {
        return 0;
    }

    let apy = (total_rewards_per_year * BASIS_POINTS * 100) / total_staked;
    apy as u64
}

pub fn estimate_rewards(staked_amount: u128, apy_basis_points: u64) -> RewardsInfo {
    let yearly_rewards = calculate_yearly_rewards(staked_amount, apy_basis_points);
    let monthly_rewards = yearly_rewards / 12;
    let weekly_rewards = yearly_rewards / 52;
    let daily_rewards = yearly_rewards / 365;

    RewardsInfo {
        staked_amount,
        pending_rewards: 0,
        apy_basis_points,
        daily_rewards,
        weekly_rewards,
        monthly_rewards,
        yearly_rewards,
    }
}

pub fn calculate_yearly_rewards(staked_amount: u128, apy_basis_points: u64) -> u128 {
    (staked_amount * apy_basis_points as u128) / (BASIS_POINTS * 100)
}

pub fn calculate_rewards_for_period(
    staked_amount: u128,
    apy_basis_points: u64,
    seconds: u64,
) -> u128 {
    let yearly_rewards = calculate_yearly_rewards(staked_amount, apy_basis_points);
    (yearly_rewards * seconds as u128) / SECONDS_PER_YEAR as u128
}

pub fn calculate_compound_rewards(
    initial_stake: u128,
    apy_basis_points: u64,
    compounds_per_year: u32,
    years: u32,
) -> u128 {
    let rate_per_compound = apy_basis_points as u128 / (compounds_per_year as u128 * 100);
    let mut amount = initial_stake;

    let total_compounds = compounds_per_year * years;
    for _ in 0..total_compounds {
        let rewards = (amount * rate_per_compound) / BASIS_POINTS;
        amount = amount.saturating_add(rewards);
    }

    amount
}

pub fn calculate_effective_apy(nominal_apy: u64, compounds_per_year: u32) -> u64 {
    if compounds_per_year <= 1 {
        return nominal_apy;
    }

    let rate = nominal_apy as f64 / 10000.0;
    let compound_rate = rate / compounds_per_year as f64;

    let effective = pow_f64(1.0 + compound_rate, compounds_per_year) - 1.0;
    (effective * 10000.0) as u64
}

fn pow_f64(base: f64, exp: u32) -> f64 {
    let mut result = 1.0;
    for _ in 0..exp {
        result *= base;
    }
    result
}

pub fn calculate_break_even_time(
    staked_amount: u128,
    apy_basis_points: u64,
    gas_cost: u128,
) -> u64 {
    if apy_basis_points == 0 || staked_amount == 0 {
        return u64::MAX;
    }

    let yearly_rewards = calculate_yearly_rewards(staked_amount, apy_basis_points);
    if yearly_rewards == 0 {
        return u64::MAX;
    }

    let seconds = (gas_cost * SECONDS_PER_YEAR as u128) / yearly_rewards;
    seconds as u64
}

pub fn calculate_optimal_compound_frequency(
    staked_amount: u128,
    apy_basis_points: u64,
    gas_cost_per_compound: u128,
) -> u32 {
    let yearly_rewards = calculate_yearly_rewards(staked_amount, apy_basis_points);

    if yearly_rewards <= gas_cost_per_compound * 365 {
        return 0;
    }

    let mut best_frequency = 1u32;
    let mut best_net_gain = yearly_rewards.saturating_sub(gas_cost_per_compound);

    for freq in [2u32, 4, 12, 26, 52, 365] {
        let total_gas = gas_cost_per_compound * freq as u128;
        if total_gas >= yearly_rewards {
            break;
        }

        let compound_amount = calculate_compound_rewards(staked_amount, apy_basis_points, freq, 1);
        let gross_gain = compound_amount.saturating_sub(staked_amount);
        let net_gain = gross_gain.saturating_sub(total_gas);

        if net_gain > best_net_gain {
            best_net_gain = net_gain;
            best_frequency = freq;
        }
    }

    best_frequency
}

pub fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        return alloc::format!("{}s", seconds);
    }

    let minutes = seconds / 60;
    if minutes < 60 {
        return alloc::format!("{}m", minutes);
    }

    let hours = minutes / 60;
    if hours < 24 {
        return alloc::format!("{}h {}m", hours, minutes % 60);
    }

    let days = hours / 24;
    if days < 30 {
        return alloc::format!("{}d {}h", days, hours % 24);
    }

    let months = days / 30;
    if months < 12 {
        return alloc::format!("{}mo {}d", months, days % 30);
    }

    let years = months / 12;
    alloc::format!("{}y {}mo", years, months % 12)
}

fn format_amount(amount: u128) -> String {
    let whole = amount / 1_000_000_000_000_000_000;
    let fraction = (amount % 1_000_000_000_000_000_000) / 10_000_000_000_000_000;

    if fraction == 0 {
        alloc::format!("{}", whole)
    } else {
        alloc::format!("{}.{:02}", whole, fraction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_apy() {
        let total_rewards = 120_000_000_000_000_000_000u128;
        let total_staked = 1_000_000_000_000_000_000_000u128;
        let apy = calculate_apy(total_rewards, total_staked);
        assert_eq!(apy, 1200);
    }

    #[test]
    fn test_estimate_rewards() {
        let staked = 1000_000_000_000_000_000_000u128;
        let apy = 1200;
        let info = estimate_rewards(staked, apy);

        assert_eq!(info.yearly_rewards, 120_000_000_000_000_000_000);
        assert!(info.daily_rewards > 0);
        assert!(info.weekly_rewards > info.daily_rewards);
        assert!(info.monthly_rewards > info.weekly_rewards);
    }

    #[test]
    fn test_compound_rewards() {
        let initial = 1000_000_000_000_000_000_000u128;
        let apy = 1200;

        let simple = calculate_yearly_rewards(initial, apy);
        let compound = calculate_compound_rewards(initial, apy, 12, 1);

        assert!(compound > initial + simple);
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(30), "30s");
        assert_eq!(format_duration(120), "2m");
        assert_eq!(format_duration(3700), "1h 1m");
        assert_eq!(format_duration(90000), "1d 1h");
    }
}
