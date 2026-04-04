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

#[test]
fn test_stake_record_new() {
    let record = StakeRecord::new();
    assert!(record.amount.is_zero());
    assert_eq!(record.tier, NodeTier::Bronze);
    assert_eq!(record.lock_start_epoch, 0);
    assert_eq!(record.lock_end_epoch, 0);
    assert!(!record.is_locked);
}

#[test]
fn test_stake_record_stake_bronze() {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(1_000), 100);
    assert_eq!(record.amount.whole(), 1_000);
    assert_eq!(record.tier, NodeTier::Bronze);
    assert_eq!(record.lock_start_epoch, 100);
    assert_eq!(record.lock_end_epoch, 100);
    assert!(!record.is_locked);
}

#[test]
fn test_stake_record_stake_silver() {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(10_000), 100);
    assert_eq!(record.tier, NodeTier::Silver);
    assert!(record.is_locked);
    assert_eq!(record.lock_end_epoch, 130);
}

#[test]
fn test_stake_record_stake_gold() {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(50_000), 100);
    assert_eq!(record.tier, NodeTier::Gold);
    assert!(record.is_locked);
    assert_eq!(record.lock_end_epoch, 190);
}

#[test]
fn test_stake_record_stake_platinum() {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(200_000), 100);
    assert_eq!(record.tier, NodeTier::Platinum);
    assert!(record.is_locked);
    assert_eq!(record.lock_end_epoch, 280);
}

#[test]
fn test_stake_record_stake_diamond() {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(1_000_000), 100);
    assert_eq!(record.tier, NodeTier::Diamond);
    assert!(record.is_locked);
    assert_eq!(record.lock_end_epoch, 465);
}

#[test]
fn test_stake_record_stake_accumulates() {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(5_000), 100);
    record.stake(TokenAmount::from_nox(5_000), 100);
    assert_eq!(record.amount.whole(), 10_000);
    assert_eq!(record.tier, NodeTier::Silver);
}

#[test]
fn test_stake_record_can_unstake_not_locked() {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(1_000), 100);
    assert!(record.can_unstake(100));
    assert!(record.can_unstake(0));
}

#[test]
fn test_stake_record_can_unstake_locked_before_end() {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(10_000), 100);
    assert!(!record.can_unstake(100));
    assert!(!record.can_unstake(129));
}

#[test]
fn test_stake_record_can_unstake_locked_at_end() {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(10_000), 100);
    assert!(record.can_unstake(130));
}

#[test]
fn test_stake_record_can_unstake_locked_after_end() {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(10_000), 100);
    assert!(record.can_unstake(200));
}

#[test]
fn test_stake_record_unstake_success() {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(1_000), 100);
    let result = record.unstake(TokenAmount::from_nox(500), 100);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().whole(), 500);
    assert_eq!(record.amount.whole(), 500);
}

#[test]
fn test_stake_record_unstake_locked() {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(10_000), 100);
    let result = record.unstake(TokenAmount::from_nox(5_000), 100);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Stake is still locked");
}

#[test]
fn test_stake_record_unstake_insufficient() {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(1_000), 100);
    let result = record.unstake(TokenAmount::from_nox(2_000), 100);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Insufficient staked amount");
}

#[test]
fn test_stake_record_unstake_updates_tier() {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(10_000), 100);
    let _ = record.unstake(TokenAmount::from_nox(5_000), 130);
    assert_eq!(record.tier, NodeTier::Bronze);
}

#[test]
fn test_stake_record_weight_zero() {
    let record = StakeRecord::new();
    assert_eq!(record.weight(), 0);
}

#[test]
fn test_stake_record_weight_bronze() {
    let mut record = StakeRecord::new();
    record.stake(TokenAmount::from_nox(10_000), 0);
    record.tier = NodeTier::Bronze;
    let weight = record.weight();
    assert!(weight > 0);
}

#[test]
fn test_staking_state_new() {
    let state = StakingState::new();
    assert!(state.stake.amount.is_zero());
    assert!(state.pending_rewards.is_zero());
    assert!(state.claimed_rewards.is_zero());
    assert_eq!(state.current_epoch, 0);
    assert_eq!(state.last_claim_epoch, 0);
    assert_eq!(state.streak, 0);
}

#[test]
fn test_staking_state_deposit() {
    let mut state = StakingState::new();
    state.deposit(TokenAmount::from_nox(10_000));
    assert_eq!(state.stake.amount.whole(), 10_000);
    assert_eq!(state.stake.tier, NodeTier::Silver);
}

#[test]
fn test_staking_state_deposit_multiple() {
    let mut state = StakingState::new();
    state.deposit(TokenAmount::from_nox(5_000));
    state.deposit(TokenAmount::from_nox(5_000));
    assert_eq!(state.stake.amount.whole(), 10_000);
}

#[test]
fn test_staking_state_withdraw_success() {
    let mut state = StakingState::new();
    state.deposit(TokenAmount::from_nox(1_000));
    let result = state.withdraw(TokenAmount::from_nox(500));
    assert!(result.is_ok());
    assert_eq!(state.stake.amount.whole(), 500);
}

#[test]
fn test_staking_state_withdraw_locked() {
    let mut state = StakingState::new();
    state.deposit(TokenAmount::from_nox(10_000));
    let result = state.withdraw(TokenAmount::from_nox(5_000));
    assert!(result.is_err());
}

#[test]
fn test_staking_state_claim_rewards_none() {
    let mut state = StakingState::new();
    let result = state.claim_rewards();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "No pending rewards");
}

#[test]
fn test_staking_state_claim_rewards_success() {
    let mut state = StakingState::new();
    state.add_rewards(TokenAmount::from_nox(100));
    state.current_epoch = 10;
    let result = state.claim_rewards();
    assert!(result.is_ok());
    assert_eq!(result.unwrap().whole(), 100);
    assert!(state.pending_rewards.is_zero());
    assert_eq!(state.claimed_rewards.whole(), 100);
    assert_eq!(state.last_claim_epoch, 10);
}

#[test]
fn test_staking_state_update_epoch() {
    let mut state = StakingState::new();
    state.update_epoch(100);
    assert_eq!(state.current_epoch, 100);
}

#[test]
fn test_staking_state_update_epoch_no_decrease() {
    let mut state = StakingState::new();
    state.update_epoch(100);
    state.update_epoch(50);
    assert_eq!(state.current_epoch, 100);
}

#[test]
fn test_staking_state_add_rewards() {
    let mut state = StakingState::new();
    state.add_rewards(TokenAmount::from_nox(50));
    state.add_rewards(TokenAmount::from_nox(50));
    assert_eq!(state.pending_rewards.whole(), 100);
}

#[test]
fn test_staking_state_total_staked() {
    let mut state = StakingState::new();
    state.deposit(TokenAmount::from_nox(50_000));
    assert_eq!(state.total_staked().whole(), 50_000);
}

#[test]
fn test_staking_state_tier() {
    let mut state = StakingState::new();
    state.deposit(TokenAmount::from_nox(50_000));
    assert_eq!(state.tier(), NodeTier::Gold);
}

#[test]
fn test_staking_state_default() {
    let state = StakingState::default();
    assert!(state.stake.amount.is_zero());
    assert_eq!(state.current_epoch, 0);
}

#[test]
fn test_calculate_epoch_reward_zero_weight() {
    let reward = calculate_epoch_reward(0, 1000, 1000);
    assert_eq!(reward, 0);
}

#[test]
fn test_calculate_epoch_reward_zero_total() {
    let reward = calculate_epoch_reward(100, 0, 1000);
    assert_eq!(reward, 0);
}

#[test]
fn test_calculate_epoch_reward_full_share() {
    let reward = calculate_epoch_reward(1000, 1000, 1000);
    assert_eq!(reward, 1000);
}

#[test]
fn test_calculate_epoch_reward_half_share() {
    let reward = calculate_epoch_reward(500, 1000, 1000);
    assert_eq!(reward, 500);
}

#[test]
fn test_calculate_epoch_emission_year_zero() {
    let emission = calculate_epoch_emission(0);
    assert_eq!(emission, 3_200_000 / 365);
}

#[test]
fn test_calculate_epoch_emission_year_one() {
    let emission = calculate_epoch_emission(365);
    assert!(emission < 3_200_000 / 365);
}

#[test]
fn test_calculate_epoch_emission_decreases_over_time() {
    let emission_y0 = calculate_epoch_emission(0);
    let emission_y1 = calculate_epoch_emission(365);
    let emission_y2 = calculate_epoch_emission(730);
    assert!(emission_y0 > emission_y1);
    assert!(emission_y1 > emission_y2);
}
