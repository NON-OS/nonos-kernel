// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

extern crate alloc;

use crate::apps::ecosystem::staking::rewards::{estimate_rewards, RewardsInfo};
use crate::test::framework::TestResult;

pub(crate) fn test_rewards_info_daily_rewards() -> TestResult {
    let info = estimate_rewards(1000_000_000_000_000_000_000, 1200);
    if info.daily_rewards == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_info_weekly_rewards() -> TestResult {
    let info = estimate_rewards(1000_000_000_000_000_000_000, 1200);
    if info.weekly_rewards == 0 {
        return TestResult::Fail;
    }
    if info.weekly_rewards <= info.daily_rewards {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_info_monthly_rewards() -> TestResult {
    let info = estimate_rewards(1000_000_000_000_000_000_000, 1200);
    if info.monthly_rewards == 0 {
        return TestResult::Fail;
    }
    if info.monthly_rewards <= info.weekly_rewards {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_info_yearly_rewards() -> TestResult {
    let info = estimate_rewards(1000_000_000_000_000_000_000, 1200);
    if info.yearly_rewards == 0 {
        return TestResult::Fail;
    }
    if info.yearly_rewards <= info.monthly_rewards {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_info_staked_amount() -> TestResult {
    let staked = 500_000_000_000_000_000_000u128;
    let info = estimate_rewards(staked, 1000);
    if info.staked_amount != staked {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_info_pending_rewards_initial() -> TestResult {
    let info = estimate_rewards(1000_000_000_000_000_000_000, 1200);
    if info.pending_rewards != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_info_apy_basis_points() -> TestResult {
    let info = estimate_rewards(1000_000_000_000_000_000_000, 1500);
    if info.apy_basis_points != 1500 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_info_apy_percentage() -> TestResult {
    let info = estimate_rewards(1000_000_000_000_000_000_000, 1200);
    let percentage = info.apy_percentage();
    if (percentage - 12.0).abs() >= 0.01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_info_apy_percentage_5() -> TestResult {
    let info = estimate_rewards(1000, 500);
    let percentage = info.apy_percentage();
    if (percentage - 5.0).abs() >= 0.01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_info_apy_percentage_20() -> TestResult {
    let info = estimate_rewards(1000, 2000);
    let percentage = info.apy_percentage();
    if (percentage - 20.0).abs() >= 0.01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_info_daily_formatted() -> TestResult {
    let info = estimate_rewards(1000_000_000_000_000_000_000, 1200);
    let formatted = info.daily_rewards_formatted();
    if formatted.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_info_weekly_formatted() -> TestResult {
    let info = estimate_rewards(1000_000_000_000_000_000_000, 1200);
    let formatted = info.weekly_rewards_formatted();
    if formatted.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_info_monthly_formatted() -> TestResult {
    let info = estimate_rewards(1000_000_000_000_000_000_000, 1200);
    let formatted = info.monthly_rewards_formatted();
    if formatted.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_info_yearly_formatted() -> TestResult {
    let info = estimate_rewards(1000_000_000_000_000_000_000, 1200);
    let formatted = info.yearly_rewards_formatted();
    if formatted.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_info_small_stake() -> TestResult {
    let info = estimate_rewards(1_000_000_000_000_000_000, 1200);
    if info.staked_amount == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_info_large_stake() -> TestResult {
    let info = estimate_rewards(10_000_000_000_000_000_000_000, 1200);
    if info.yearly_rewards == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_info_zero_stake() -> TestResult {
    let info = estimate_rewards(0, 1200);
    if info.yearly_rewards != 0 {
        return TestResult::Fail;
    }
    if info.monthly_rewards != 0 {
        return TestResult::Fail;
    }
    if info.weekly_rewards != 0 {
        return TestResult::Fail;
    }
    if info.daily_rewards != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_info_zero_apy() -> TestResult {
    let info = estimate_rewards(1000_000_000_000_000_000_000, 0);
    if info.yearly_rewards != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_reward_ratio() -> TestResult {
    let info = estimate_rewards(1000_000_000_000_000_000_000, 1200);
    let yearly = info.yearly_rewards;
    let monthly = info.monthly_rewards;
    if yearly / 12 != monthly {
        return TestResult::Fail;
    }
    TestResult::Pass
}
