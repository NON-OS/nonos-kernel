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

use crate::daemon::*;
use crate::test::framework::TestResult;

pub(crate) fn test_stake_record_new() -> TestResult {
    let record = StakeRecord::new();
    if !record.amount.is_zero() {
        return TestResult::Fail;
    }
    if record.tier != NodeTier::Bronze {
        return TestResult::Fail;
    }
    if record.lock_start_epoch != 0 {
        return TestResult::Fail;
    }
    if record.lock_end_epoch != 0 {
        return TestResult::Fail;
    }
    if record.is_locked {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stake_record_stake_bronze() -> TestResult {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(1_000), 100);
    if record.amount.whole() != 1_000 {
        return TestResult::Fail;
    }
    if record.tier != NodeTier::Bronze {
        return TestResult::Fail;
    }
    if record.lock_start_epoch != 100 {
        return TestResult::Fail;
    }
    if record.lock_end_epoch != 100 {
        return TestResult::Fail;
    }
    if record.is_locked {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stake_record_stake_silver() -> TestResult {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(10_000), 100);
    if record.tier != NodeTier::Silver {
        return TestResult::Fail;
    }
    if !record.is_locked {
        return TestResult::Fail;
    }
    if record.lock_end_epoch != 130 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stake_record_stake_gold() -> TestResult {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(50_000), 100);
    if record.tier != NodeTier::Gold {
        return TestResult::Fail;
    }
    if !record.is_locked {
        return TestResult::Fail;
    }
    if record.lock_end_epoch != 190 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stake_record_stake_platinum() -> TestResult {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(200_000), 100);
    if record.tier != NodeTier::Platinum {
        return TestResult::Fail;
    }
    if !record.is_locked {
        return TestResult::Fail;
    }
    if record.lock_end_epoch != 280 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stake_record_stake_diamond() -> TestResult {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(1_000_000), 100);
    if record.tier != NodeTier::Diamond {
        return TestResult::Fail;
    }
    if !record.is_locked {
        return TestResult::Fail;
    }
    if record.lock_end_epoch != 465 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stake_record_stake_accumulates() -> TestResult {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(5_000), 100);
    record.stake(TokenAmount::from_nox(5_000), 100);
    if record.amount.whole() != 10_000 {
        return TestResult::Fail;
    }
    if record.tier != NodeTier::Silver {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stake_record_can_unstake_not_locked() -> TestResult {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(1_000), 100);
    if !record.can_unstake(100) {
        return TestResult::Fail;
    }
    if !record.can_unstake(0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stake_record_can_unstake_locked_before_end() -> TestResult {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(10_000), 100);
    if record.can_unstake(100) {
        return TestResult::Fail;
    }
    if record.can_unstake(129) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stake_record_can_unstake_locked_at_end() -> TestResult {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(10_000), 100);
    if !record.can_unstake(130) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stake_record_can_unstake_locked_after_end() -> TestResult {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(10_000), 100);
    if !record.can_unstake(200) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stake_record_unstake_success() -> TestResult {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(1_000), 100);
    let result = record.unstake(TokenAmount::from_nox(500), 100);
    if !result.is_ok() {
        return TestResult::Fail;
    }
    if result.unwrap().whole() != 500 {
        return TestResult::Fail;
    }
    if record.amount.whole() != 500 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stake_record_unstake_locked() -> TestResult {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(10_000), 100);
    let result = record.unstake(TokenAmount::from_nox(5_000), 100);
    if !result.is_err() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != "Stake is still locked" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stake_record_unstake_insufficient() -> TestResult {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(1_000), 100);
    let result = record.unstake(TokenAmount::from_nox(2_000), 100);
    if !result.is_err() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != "Insufficient staked amount" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stake_record_unstake_updates_tier() -> TestResult {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(10_000), 100);
    let _ = record.unstake(TokenAmount::from_nox(5_000), 130);
    if record.tier != NodeTier::Bronze {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stake_record_weight_zero() -> TestResult {
    let record = StakeRecord::new();
    if record.weight() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stake_record_weight_bronze() -> TestResult {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(10_000), 0);
    record.tier = NodeTier::Bronze;
    let weight = record.weight();
    if !(weight > 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_staking_state_new() -> TestResult {
    let state = StakingState::new();
    if !state.stake.amount.is_zero() {
        return TestResult::Fail;
    }
    if !state.pending_rewards.is_zero() {
        return TestResult::Fail;
    }
    if !state.claimed_rewards.is_zero() {
        return TestResult::Fail;
    }
    if state.current_epoch != 0 {
        return TestResult::Fail;
    }
    if state.last_claim_epoch != 0 {
        return TestResult::Fail;
    }
    if state.streak != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_staking_state_deposit() -> TestResult {
    let mut state = StakingState::new();
    state.deposit(TokenAmount::from_nox(10_000));
    if state.stake.amount.whole() != 10_000 {
        return TestResult::Fail;
    }
    if state.stake.tier != NodeTier::Silver {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_staking_state_deposit_multiple() -> TestResult {
    let mut state = StakingState::new();
    state.deposit(TokenAmount::from_nox(5_000));
    state.deposit(TokenAmount::from_nox(5_000));
    if state.stake.amount.whole() != 10_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_staking_state_withdraw_success() -> TestResult {
    let mut state = StakingState::new();
    state.deposit(TokenAmount::from_nox(1_000));
    let result = state.withdraw(TokenAmount::from_nox(500));
    if !result.is_ok() {
        return TestResult::Fail;
    }
    if state.stake.amount.whole() != 500 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_staking_state_withdraw_locked() -> TestResult {
    let mut state = StakingState::new();
    state.deposit(TokenAmount::from_nox(10_000));
    let result = state.withdraw(TokenAmount::from_nox(5_000));
    if !result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_staking_state_claim_rewards_none() -> TestResult {
    let mut state = StakingState::new();
    let result = state.claim_rewards();
    if !result.is_err() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != "No pending rewards" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_staking_state_claim_rewards_success() -> TestResult {
    let mut state = StakingState::new();
    state.add_rewards(TokenAmount::from_nox(100));
    state.current_epoch = 10;
    let result = state.claim_rewards();
    if !result.is_ok() {
        return TestResult::Fail;
    }
    if result.unwrap().whole() != 100 {
        return TestResult::Fail;
    }
    if !state.pending_rewards.is_zero() {
        return TestResult::Fail;
    }
    if state.claimed_rewards.whole() != 100 {
        return TestResult::Fail;
    }
    if state.last_claim_epoch != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_staking_state_update_epoch() -> TestResult {
    let mut state = StakingState::new();
    state.update_epoch(100);
    if state.current_epoch != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_staking_state_update_epoch_no_decrease() -> TestResult {
    let mut state = StakingState::new();
    state.update_epoch(100);
    state.update_epoch(50);
    if state.current_epoch != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_staking_state_add_rewards() -> TestResult {
    let mut state = StakingState::new();
    state.add_rewards(TokenAmount::from_nox(50));
    state.add_rewards(TokenAmount::from_nox(50));
    if state.pending_rewards.whole() != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_staking_state_total_staked() -> TestResult {
    let mut state = StakingState::new();
    state.deposit(TokenAmount::from_nox(50_000));
    if state.total_staked().whole() != 50_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_staking_state_tier() -> TestResult {
    let mut state = StakingState::new();
    state.deposit(TokenAmount::from_nox(50_000));
    if state.tier() != NodeTier::Gold {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_staking_state_default() -> TestResult {
    let state = StakingState::default();
    if !state.stake.amount.is_zero() {
        return TestResult::Fail;
    }
    if state.current_epoch != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_calculate_epoch_reward_zero_weight() -> TestResult {
    let reward = calculate_epoch_reward(0, 1000, 1000);
    if reward != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_calculate_epoch_reward_zero_total() -> TestResult {
    let reward = calculate_epoch_reward(100, 0, 1000);
    if reward != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_calculate_epoch_reward_full_share() -> TestResult {
    let reward = calculate_epoch_reward(1000, 1000, 1000);
    if reward != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_calculate_epoch_reward_half_share() -> TestResult {
    let reward = calculate_epoch_reward(500, 1000, 1000);
    if reward != 500 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_calculate_epoch_emission_year_zero() -> TestResult {
    let emission = calculate_epoch_emission(0);
    if emission != 3_200_000 / 365 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_calculate_epoch_emission_year_one() -> TestResult {
    let emission = calculate_epoch_emission(365);
    if !(emission < 3_200_000 / 365) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_calculate_epoch_emission_decreases_over_time() -> TestResult {
    let emission_y0 = calculate_epoch_emission(0);
    let emission_y1 = calculate_epoch_emission(365);
    let emission_y2 = calculate_epoch_emission(730);
    if !(emission_y0 > emission_y1) {
        return TestResult::Fail;
    }
    if !(emission_y1 > emission_y2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
