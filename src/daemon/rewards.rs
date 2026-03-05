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

//! Rewards calculation and tracking.

use super::types::{NodeTier, QualityScore, TokenAmount};
use super::staking::{calculate_epoch_emission, calculate_epoch_reward};

pub const MAX_REWARD_HISTORY: usize = 30;

#[derive(Clone, Copy)]
pub struct EpochReward {
    pub epoch: u64,
    pub amount: TokenAmount,
    pub stake_weight: u64,
    pub quality_bonus: u8,
    pub streak_bonus: u8,
    pub claimed: bool,
}

impl EpochReward {
    pub const fn empty() -> Self {
        Self {
            epoch: 0,
            amount: TokenAmount::zero(),
            stake_weight: 0,
            quality_bonus: 0,
            streak_bonus: 0,
            claimed: false,
        }
    }
}

#[derive(Clone, Copy)]
pub struct RewardsTracker {
    pub history: [EpochReward; MAX_REWARD_HISTORY],
    pub history_count: usize,
    pub total_earned: TokenAmount,
    pub total_claimed: TokenAmount,
    pub current_streak: u32,
    pub best_streak: u32,
}

impl RewardsTracker {
    pub const fn new() -> Self {
        Self {
            history: [EpochReward::empty(); MAX_REWARD_HISTORY],
            history_count: 0,
            total_earned: TokenAmount::zero(),
            total_claimed: TokenAmount::zero(),
            current_streak: 0,
            best_streak: 0,
        }
    }

    pub fn add_epoch_reward(
        &mut self,
        epoch: u64,
        stake_weight: u64,
        total_network_weight: u64,
        quality: &QualityScore,
        _tier: NodeTier,
    ) {
        let base_emission = calculate_epoch_emission(epoch);
        let base_reward = calculate_epoch_reward(stake_weight, total_network_weight, base_emission);

        let quality_score = quality.total();
        let quality_bonus = if quality_score >= 95 {
            20
        } else if quality_score >= 90 {
            15
        } else if quality_score >= 80 {
            10
        } else if quality_score >= 70 {
            5
        } else {
            0
        };

        let streak_bonus = if self.current_streak >= 30 {
            15
        } else if self.current_streak >= 14 {
            10
        } else if self.current_streak >= 7 {
            5
        } else {
            0
        };

        let total_bonus = quality_bonus + streak_bonus;
        let bonus_amount = (base_reward as u128 * total_bonus as u128) / 100;
        let final_reward = base_reward as u128 + bonus_amount;

        let reward = EpochReward {
            epoch,
            amount: TokenAmount {
                raw: final_reward * 1_000_000_000_000_000_000 / 1_000_000,
                decimals: 18,
            },
            stake_weight,
            quality_bonus,
            streak_bonus,
            claimed: false,
        };

        if self.history_count < MAX_REWARD_HISTORY {
            self.history[self.history_count] = reward;
            self.history_count += 1;
        } else {
            for i in 0..MAX_REWARD_HISTORY - 1 {
                self.history[i] = self.history[i + 1];
            }
            self.history[MAX_REWARD_HISTORY - 1] = reward;
        }

        if let Some(total) = self.total_earned.checked_add(&reward.amount) {
            self.total_earned = total;
        }

        if quality_score >= 70 {
            self.current_streak += 1;
            if self.current_streak > self.best_streak {
                self.best_streak = self.current_streak;
            }
        } else {
            self.current_streak = 0;
        }
    }

    pub fn claim_epoch(&mut self, epoch: u64) -> Option<TokenAmount> {
        for i in 0..self.history_count {
            if self.history[i].epoch == epoch && !self.history[i].claimed {
                self.history[i].claimed = true;
                let amount = self.history[i].amount;
                if let Some(total) = self.total_claimed.checked_add(&amount) {
                    self.total_claimed = total;
                }
                return Some(amount);
            }
        }
        None
    }

    pub fn claim_all(&mut self) -> TokenAmount {
        let mut total = TokenAmount::zero();
        for i in 0..self.history_count {
            if !self.history[i].claimed {
                self.history[i].claimed = true;
                if let Some(sum) = total.checked_add(&self.history[i].amount) {
                    total = sum;
                }
            }
        }
        if let Some(claimed) = self.total_claimed.checked_add(&total) {
            self.total_claimed = claimed;
        }
        total
    }

    pub fn pending(&self) -> TokenAmount {
        let mut total = TokenAmount::zero();
        for i in 0..self.history_count {
            if !self.history[i].claimed {
                if let Some(sum) = total.checked_add(&self.history[i].amount) {
                    total = sum;
                }
            }
        }
        total
    }

    pub fn pending_count(&self) -> usize {
        let mut count = 0;
        for i in 0..self.history_count {
            if !self.history[i].claimed {
                count += 1;
            }
        }
        count
    }
}

impl Default for RewardsTracker {
    fn default() -> Self {
        Self::new()
    }
}
