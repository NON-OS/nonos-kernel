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
fn test_epoch_reward_empty() {
    let reward = EpochReward::empty();
    assert_eq!(reward.epoch, 0);
    assert!(reward.amount.is_zero());
    assert_eq!(reward.stake_weight, 0);
    assert_eq!(reward.quality_bonus, 0);
    assert_eq!(reward.streak_bonus, 0);
    assert!(!reward.claimed);
}

#[test]
fn test_rewards_tracker_new() {
    let tracker = RewardsTracker::new();
    assert_eq!(tracker.history_count, 0);
    assert!(tracker.total_earned.is_zero());
    assert!(tracker.total_claimed.is_zero());
    assert_eq!(tracker.current_streak, 0);
    assert_eq!(tracker.best_streak, 0);
}

#[test]
fn test_rewards_tracker_add_epoch_reward() {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    assert_eq!(tracker.history_count, 1);
    assert!(!tracker.total_earned.is_zero());
}

#[test]
fn test_rewards_tracker_add_epoch_reward_updates_history() {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    assert_eq!(tracker.history[0].epoch, 100);
    assert_eq!(tracker.history[0].stake_weight, 1000);
}

#[test]
fn test_rewards_tracker_add_epoch_reward_quality_bonus_high() {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    assert_eq!(tracker.history[0].quality_bonus, 20);
}

#[test]
fn test_rewards_tracker_add_epoch_reward_quality_bonus_90() {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore {
        uptime: 90,
        success_rate: 90,
        latency_score: 90,
        reliability: 90,
    };
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    assert_eq!(tracker.history[0].quality_bonus, 15);
}

#[test]
fn test_rewards_tracker_add_epoch_reward_quality_bonus_80() {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore {
        uptime: 80,
        success_rate: 80,
        latency_score: 80,
        reliability: 80,
    };
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    assert_eq!(tracker.history[0].quality_bonus, 10);
}

#[test]
fn test_rewards_tracker_add_epoch_reward_quality_bonus_70() {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore {
        uptime: 70,
        success_rate: 70,
        latency_score: 70,
        reliability: 70,
    };
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    assert_eq!(tracker.history[0].quality_bonus, 5);
}

#[test]
fn test_rewards_tracker_add_epoch_reward_quality_bonus_low() {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore {
        uptime: 60,
        success_rate: 60,
        latency_score: 60,
        reliability: 60,
    };
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    assert_eq!(tracker.history[0].quality_bonus, 0);
}

#[test]
fn test_rewards_tracker_streak_bonus_30_days() {
    let mut tracker = RewardsTracker::new();
    tracker.current_streak = 30;
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    assert_eq!(tracker.history[0].streak_bonus, 15);
}

#[test]
fn test_rewards_tracker_streak_bonus_14_days() {
    let mut tracker = RewardsTracker::new();
    tracker.current_streak = 14;
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    assert_eq!(tracker.history[0].streak_bonus, 10);
}

#[test]
fn test_rewards_tracker_streak_bonus_7_days() {
    let mut tracker = RewardsTracker::new();
    tracker.current_streak = 7;
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    assert_eq!(tracker.history[0].streak_bonus, 5);
}

#[test]
fn test_rewards_tracker_streak_bonus_none() {
    let mut tracker = RewardsTracker::new();
    tracker.current_streak = 3;
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    assert_eq!(tracker.history[0].streak_bonus, 0);
}

#[test]
fn test_rewards_tracker_streak_increments() {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    assert_eq!(tracker.current_streak, 1);
    tracker.add_epoch_reward(101, 1000, 10000, &quality, NodeTier::Gold);
    assert_eq!(tracker.current_streak, 2);
}

#[test]
fn test_rewards_tracker_streak_resets_on_low_quality() {
    let mut tracker = RewardsTracker::new();
    tracker.current_streak = 10;
    let low_quality = QualityScore {
        uptime: 50,
        success_rate: 50,
        latency_score: 50,
        reliability: 50,
    };
    tracker.add_epoch_reward(100, 1000, 10000, &low_quality, NodeTier::Gold);
    assert_eq!(tracker.current_streak, 0);
}

#[test]
fn test_rewards_tracker_best_streak_updates() {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    for i in 0..10 {
        tracker.add_epoch_reward(i, 1000, 10000, &quality, NodeTier::Gold);
    }
    assert_eq!(tracker.best_streak, 10);
}

#[test]
fn test_rewards_tracker_history_rotation() {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    for i in 0..40 {
        tracker.add_epoch_reward(i as u64, 1000, 10000, &quality, NodeTier::Gold);
    }
    assert_eq!(tracker.history_count, MAX_REWARD_HISTORY);
    assert_eq!(tracker.history[MAX_REWARD_HISTORY - 1].epoch, 39);
}

#[test]
fn test_rewards_tracker_claim_epoch() {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    let claimed = tracker.claim_epoch(100);
    assert!(claimed.is_some());
    assert!(tracker.history[0].claimed);
    assert!(!tracker.total_claimed.is_zero());
}

#[test]
fn test_rewards_tracker_claim_epoch_not_found() {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    let claimed = tracker.claim_epoch(999);
    assert!(claimed.is_none());
}

#[test]
fn test_rewards_tracker_claim_epoch_already_claimed() {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    tracker.claim_epoch(100);
    let claimed = tracker.claim_epoch(100);
    assert!(claimed.is_none());
}

#[test]
fn test_rewards_tracker_claim_all() {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    tracker.add_epoch_reward(101, 1000, 10000, &quality, NodeTier::Gold);
    tracker.add_epoch_reward(102, 1000, 10000, &quality, NodeTier::Gold);
    let total = tracker.claim_all();
    assert!(!total.is_zero());
    for i in 0..tracker.history_count {
        assert!(tracker.history[i].claimed);
    }
}

#[test]
fn test_rewards_tracker_claim_all_partial() {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    tracker.add_epoch_reward(101, 1000, 10000, &quality, NodeTier::Gold);
    tracker.claim_epoch(100);
    let total = tracker.claim_all();
    assert!(!total.is_zero());
}

#[test]
fn test_rewards_tracker_claim_all_empty() {
    let mut tracker = RewardsTracker::new();
    let total = tracker.claim_all();
    assert!(total.is_zero());
}

#[test]
fn test_rewards_tracker_pending_none() {
    let tracker = RewardsTracker::new();
    assert!(tracker.pending().is_zero());
}

#[test]
fn test_rewards_tracker_pending_all() {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    tracker.add_epoch_reward(101, 1000, 10000, &quality, NodeTier::Gold);
    let pending = tracker.pending();
    assert!(!pending.is_zero());
}

#[test]
fn test_rewards_tracker_pending_after_claim() {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    tracker.add_epoch_reward(101, 1000, 10000, &quality, NodeTier::Gold);
    tracker.claim_epoch(100);
    let pending = tracker.pending();
    assert!(!pending.is_zero());
}

#[test]
fn test_rewards_tracker_pending_count_none() {
    let tracker = RewardsTracker::new();
    assert_eq!(tracker.pending_count(), 0);
}

#[test]
fn test_rewards_tracker_pending_count_all() {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    tracker.add_epoch_reward(101, 1000, 10000, &quality, NodeTier::Gold);
    tracker.add_epoch_reward(102, 1000, 10000, &quality, NodeTier::Gold);
    assert_eq!(tracker.pending_count(), 3);
}

#[test]
fn test_rewards_tracker_pending_count_partial() {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    tracker.add_epoch_reward(101, 1000, 10000, &quality, NodeTier::Gold);
    tracker.add_epoch_reward(102, 1000, 10000, &quality, NodeTier::Gold);
    tracker.claim_epoch(101);
    assert_eq!(tracker.pending_count(), 2);
}

#[test]
fn test_rewards_tracker_default() {
    let tracker = RewardsTracker::default();
    assert_eq!(tracker.history_count, 0);
    assert_eq!(tracker.current_streak, 0);
    assert!(tracker.total_earned.is_zero());
}

#[test]
fn test_rewards_constants() {
    assert_eq!(MAX_REWARD_HISTORY, 30);
}
