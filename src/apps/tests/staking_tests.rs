// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

extern crate alloc;

use crate::apps::ecosystem::staking::rewards::{
    calculate_apy, calculate_compound_rewards, calculate_effective_apy,
    calculate_rewards_for_period, calculate_yearly_rewards, estimate_rewards, format_duration,
};
use crate::apps::ecosystem::staking::state::{
    Network, NOX_TOKEN_MAINNET, NOX_TOKEN_SEPOLIA, STAKING_CONTRACT_MAINNET,
    STAKING_CONTRACT_SEPOLIA,
};
use crate::test::framework::TestResult;

pub(crate) fn test_network_mainnet_staking_contract() -> TestResult {
    let contract = Network::Mainnet.staking_contract();
    if contract != STAKING_CONTRACT_MAINNET {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_network_sepolia_staking_contract() -> TestResult {
    let contract = Network::Sepolia.staking_contract();
    if contract != STAKING_CONTRACT_SEPOLIA {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_network_mainnet_nox_token() -> TestResult {
    let token = Network::Mainnet.nox_token();
    if token != NOX_TOKEN_MAINNET {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_network_sepolia_nox_token() -> TestResult {
    let token = Network::Sepolia.nox_token();
    if token != NOX_TOKEN_SEPOLIA {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_network_mainnet_chain_id() -> TestResult {
    let chain_id = Network::Mainnet.chain_id();
    if chain_id != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_network_sepolia_chain_id() -> TestResult {
    let chain_id = Network::Sepolia.chain_id();
    if chain_id != 11155111 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_network_equality() -> TestResult {
    if Network::Mainnet != Network::Mainnet {
        return TestResult::Fail;
    }
    if Network::Sepolia != Network::Sepolia {
        return TestResult::Fail;
    }
    if Network::Mainnet == Network::Sepolia {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_network_clone() -> TestResult {
    let network = Network::Mainnet;
    let cloned = network.clone();
    if network != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_network_copy() -> TestResult {
    let network = Network::Sepolia;
    let copied = network;
    if network != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_calculate_apy() -> TestResult {
    let total_rewards = 120_000_000_000_000_000_000u128;
    let total_staked = 1_000_000_000_000_000_000_000u128;
    let apy = calculate_apy(total_rewards, total_staked);
    if apy != 1200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_calculate_apy_zero_staked() -> TestResult {
    let apy = calculate_apy(100, 0);
    if apy != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_calculate_apy_zero_rewards() -> TestResult {
    let apy = calculate_apy(0, 1000);
    if apy != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_estimate_rewards() -> TestResult {
    let staked = 1000_000_000_000_000_000_000u128;
    let apy = 1200;
    let info = estimate_rewards(staked, apy);
    if info.yearly_rewards != 120_000_000_000_000_000_000 {
        return TestResult::Fail;
    }
    if info.daily_rewards == 0 {
        return TestResult::Fail;
    }
    if info.weekly_rewards <= info.daily_rewards {
        return TestResult::Fail;
    }
    if info.monthly_rewards <= info.weekly_rewards {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_estimate_rewards_staked_amount() -> TestResult {
    let staked = 500_000_000_000_000_000_000u128;
    let info = estimate_rewards(staked, 1000);
    if info.staked_amount != staked {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_estimate_rewards_apy() -> TestResult {
    let info = estimate_rewards(1000, 1500);
    if info.apy_basis_points != 1500 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_calculate_yearly_rewards() -> TestResult {
    let staked = 1000_000_000_000_000_000_000u128;
    let apy = 1200;
    let yearly = calculate_yearly_rewards(staked, apy);
    if yearly != 120_000_000_000_000_000_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_calculate_yearly_rewards_zero_stake() -> TestResult {
    let yearly = calculate_yearly_rewards(0, 1200);
    if yearly != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_calculate_yearly_rewards_zero_apy() -> TestResult {
    let yearly = calculate_yearly_rewards(1000, 0);
    if yearly != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_calculate_rewards_for_period() -> TestResult {
    let staked = 1000_000_000_000_000_000_000u128;
    let apy = 1200;
    let one_day = 24 * 60 * 60;
    let rewards = calculate_rewards_for_period(staked, apy, one_day);
    if rewards == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_calculate_rewards_for_period_zero_seconds() -> TestResult {
    let rewards = calculate_rewards_for_period(1000, 1200, 0);
    if rewards != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_compound_rewards_greater_than_simple() -> TestResult {
    let initial = 1000_000_000_000_000_000_000u128;
    let apy = 1200;
    let simple = calculate_yearly_rewards(initial, apy);
    let compound = calculate_compound_rewards(initial, apy, 12, 1);
    if compound <= initial + simple {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_compound_rewards_once() -> TestResult {
    let initial = 1000_000_000_000_000_000_000u128;
    let compound = calculate_compound_rewards(initial, 1000, 1, 1);
    if compound <= initial {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_calculate_effective_apy_single_compound() -> TestResult {
    let effective = calculate_effective_apy(1200, 1);
    if effective != 1200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_calculate_effective_apy_multiple_compounds() -> TestResult {
    let effective = calculate_effective_apy(1200, 12);
    if effective <= 1200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_duration_seconds() -> TestResult {
    let formatted = format_duration(30);
    if formatted != "30s" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_duration_minutes() -> TestResult {
    let formatted = format_duration(120);
    if formatted != "2m" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_duration_hours() -> TestResult {
    let formatted = format_duration(3700);
    if formatted != "1h 1m" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_duration_days() -> TestResult {
    let formatted = format_duration(90000);
    if formatted != "1d 1h" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_duration_months() -> TestResult {
    let formatted = format_duration(31 * 24 * 60 * 60);
    if !formatted.contains("mo") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_info_apy_percentage() -> TestResult {
    let info = estimate_rewards(1000, 1200);
    let percentage = info.apy_percentage();
    if (percentage - 12.0).abs() >= 0.01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
