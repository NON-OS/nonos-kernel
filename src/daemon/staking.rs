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

//! NOX token staking functionality.

use super::types::{NodeTier, TokenAmount};

#[derive(Clone, Copy, Debug)]
pub struct StakeRecord {
    pub amount: TokenAmount,
    pub tier: NodeTier,
    pub lock_start_epoch: u64,
    pub lock_end_epoch: u64,
    pub is_locked: bool,
}

impl StakeRecord {
    pub const fn new() -> Self {
        Self {
            amount: TokenAmount::zero(),
            tier: NodeTier::Bronze,
            lock_start_epoch: 0,
            lock_end_epoch: 0,
            is_locked: false,
        }
    }

    pub fn stake(&mut self, amount: TokenAmount, current_epoch: u64) {
        self.amount = match self.amount.checked_add(&amount) {
            Some(total) => total,
            None => return,
        };
        self.tier = NodeTier::from_stake(self.amount.whole());
        self.lock_start_epoch = current_epoch;
        self.lock_end_epoch = current_epoch + (self.tier.lock_days() as u64);
        self.is_locked = self.tier.lock_days() > 0;
    }

    pub fn can_unstake(&self, current_epoch: u64) -> bool {
        !self.is_locked || current_epoch >= self.lock_end_epoch
    }

    pub fn unstake(&mut self, amount: TokenAmount, current_epoch: u64) -> Result<TokenAmount, &'static str> {
        if !self.can_unstake(current_epoch) {
            return Err("Stake is still locked");
        }

        match self.amount.checked_sub(&amount) {
            Some(remaining) => {
                self.amount = remaining;
                self.tier = NodeTier::from_stake(self.amount.whole());
                Ok(amount)
            }
            None => Err("Insufficient staked amount"),
        }
    }

    pub fn weight(&self) -> u64 {
        let stake = self.amount.whole();
        let sqrt_stake = isqrt(stake);
        (sqrt_stake * self.tier.multiplier() as u64) / 100
    }
}

fn isqrt(n: u64) -> u64 {
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

#[derive(Clone, Copy)]
pub struct StakingState {
    pub stake: StakeRecord,
    pub pending_rewards: TokenAmount,
    pub claimed_rewards: TokenAmount,
    pub current_epoch: u64,
    pub last_claim_epoch: u64,
    pub streak: u32,
}

impl StakingState {
    pub const fn new() -> Self {
        Self {
            stake: StakeRecord::new(),
            pending_rewards: TokenAmount::zero(),
            claimed_rewards: TokenAmount::zero(),
            current_epoch: 0,
            last_claim_epoch: 0,
            streak: 0,
        }
    }

    pub fn deposit(&mut self, amount: TokenAmount) {
        self.stake.stake(amount, self.current_epoch);
    }

    pub fn withdraw(&mut self, amount: TokenAmount) -> Result<TokenAmount, &'static str> {
        self.stake.unstake(amount, self.current_epoch)
    }

    pub fn claim_rewards(&mut self) -> Result<TokenAmount, &'static str> {
        if self.pending_rewards.is_zero() {
            return Err("No pending rewards");
        }

        let rewards = self.pending_rewards;
        self.claimed_rewards = match self.claimed_rewards.checked_add(&rewards) {
            Some(total) => total,
            None => return Err("Overflow"),
        };
        self.pending_rewards = TokenAmount::zero();
        self.last_claim_epoch = self.current_epoch;

        Ok(rewards)
    }

    pub fn update_epoch(&mut self, new_epoch: u64) {
        if new_epoch > self.current_epoch {
            self.current_epoch = new_epoch;
        }
    }

    pub fn add_rewards(&mut self, amount: TokenAmount) {
        if let Some(total) = self.pending_rewards.checked_add(&amount) {
            self.pending_rewards = total;
        }
    }

    pub fn total_staked(&self) -> TokenAmount {
        self.stake.amount
    }

    pub fn tier(&self) -> NodeTier {
        self.stake.tier
    }
}

impl Default for StakingState {
    fn default() -> Self {
        Self::new()
    }
}

pub fn calculate_epoch_reward(stake_weight: u64, total_weight: u64, epoch_emission: u64) -> u64 {
    if total_weight == 0 {
        return 0;
    }
    (stake_weight as u128 * epoch_emission as u128 / total_weight as u128) as u64
}

pub fn calculate_epoch_emission(epoch: u64) -> u64 {
    let year = epoch / 365;
    let base_yearly = 3_200_000u64;

    let mut emission = base_yearly;
    for _ in 0..year {
        emission = (emission * 85) / 100;
    }

    emission / 365
}
