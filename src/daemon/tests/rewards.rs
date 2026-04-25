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

pub(crate) fn test_epoch_reward_empty() -> TestResult {
    let reward = EpochReward::empty();
    if reward.epoch != 0 {
        return TestResult::Fail;
    }
    if !reward.amount.is_zero() {
        return TestResult::Fail;
    }
    if reward.stake_weight != 0 {
        return TestResult::Fail;
    }
    if reward.quality_bonus != 0 {
        return TestResult::Fail;
    }
    if reward.streak_bonus != 0 {
        return TestResult::Fail;
    }
    if reward.claimed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_new() -> TestResult {
    let tracker = RewardsTracker::new();
    if tracker.history_count != 0 {
        return TestResult::Fail;
    }
    if !tracker.total_earned.is_zero() {
        return TestResult::Fail;
    }
    if !tracker.total_claimed.is_zero() {
        return TestResult::Fail;
    }
    if tracker.current_streak != 0 {
        return TestResult::Fail;
    }
    if tracker.best_streak != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_add_epoch_reward() -> TestResult {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    if tracker.history_count != 1 {
        return TestResult::Fail;
    }
    if tracker.total_earned.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_add_epoch_reward_updates_history() -> TestResult {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    if tracker.history[0].epoch != 100 {
        return TestResult::Fail;
    }
    if tracker.history[0].stake_weight != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_add_epoch_reward_quality_bonus_high() -> TestResult {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    if tracker.history[0].quality_bonus != 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_add_epoch_reward_quality_bonus_90() -> TestResult {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore { uptime: 90, success_rate: 90, latency_score: 90, reliability: 90 };
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    if tracker.history[0].quality_bonus != 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_add_epoch_reward_quality_bonus_80() -> TestResult {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore { uptime: 80, success_rate: 80, latency_score: 80, reliability: 80 };
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    if tracker.history[0].quality_bonus != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_add_epoch_reward_quality_bonus_70() -> TestResult {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore { uptime: 70, success_rate: 70, latency_score: 70, reliability: 70 };
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    if tracker.history[0].quality_bonus != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_add_epoch_reward_quality_bonus_low() -> TestResult {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore { uptime: 60, success_rate: 60, latency_score: 60, reliability: 60 };
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    if tracker.history[0].quality_bonus != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_streak_bonus_30_days() -> TestResult {
    let mut tracker = RewardsTracker::new();
    tracker.current_streak = 30;
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    if tracker.history[0].streak_bonus != 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_streak_bonus_14_days() -> TestResult {
    let mut tracker = RewardsTracker::new();
    tracker.current_streak = 14;
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    if tracker.history[0].streak_bonus != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_streak_bonus_7_days() -> TestResult {
    let mut tracker = RewardsTracker::new();
    tracker.current_streak = 7;
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    if tracker.history[0].streak_bonus != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_streak_bonus_none() -> TestResult {
    let mut tracker = RewardsTracker::new();
    tracker.current_streak = 3;
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    if tracker.history[0].streak_bonus != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_streak_increments() -> TestResult {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    if tracker.current_streak != 1 {
        return TestResult::Fail;
    }
    tracker.add_epoch_reward(101, 1000, 10000, &quality, NodeTier::Gold);
    if tracker.current_streak != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_streak_resets_on_low_quality() -> TestResult {
    let mut tracker = RewardsTracker::new();
    tracker.current_streak = 10;
    let low_quality =
        QualityScore { uptime: 50, success_rate: 50, latency_score: 50, reliability: 50 };
    tracker.add_epoch_reward(100, 1000, 10000, &low_quality, NodeTier::Gold);
    if tracker.current_streak != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_best_streak_updates() -> TestResult {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    for i in 0..10 {
        tracker.add_epoch_reward(i, 1000, 10000, &quality, NodeTier::Gold);
    }
    if tracker.best_streak != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_history_rotation() -> TestResult {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    for i in 0..40 {
        tracker.add_epoch_reward(i as u64, 1000, 10000, &quality, NodeTier::Gold);
    }
    if tracker.history_count != MAX_REWARD_HISTORY {
        return TestResult::Fail;
    }
    if tracker.history[MAX_REWARD_HISTORY - 1].epoch != 39 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_claim_epoch() -> TestResult {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    let claimed = tracker.claim_epoch(100);
    if claimed.is_none() {
        return TestResult::Fail;
    }
    if !tracker.history[0].claimed {
        return TestResult::Fail;
    }
    if tracker.total_claimed.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_claim_epoch_not_found() -> TestResult {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    let claimed = tracker.claim_epoch(999);
    if claimed.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_claim_epoch_already_claimed() -> TestResult {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    tracker.claim_epoch(100);
    let claimed = tracker.claim_epoch(100);
    if claimed.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_claim_all() -> TestResult {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    tracker.add_epoch_reward(101, 1000, 10000, &quality, NodeTier::Gold);
    tracker.add_epoch_reward(102, 1000, 10000, &quality, NodeTier::Gold);
    let total = tracker.claim_all();
    if total.is_zero() {
        return TestResult::Fail;
    }
    for i in 0..tracker.history_count {
        if !tracker.history[i].claimed {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_claim_all_partial() -> TestResult {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    tracker.add_epoch_reward(101, 1000, 10000, &quality, NodeTier::Gold);
    tracker.claim_epoch(100);
    let total = tracker.claim_all();
    if total.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_claim_all_empty() -> TestResult {
    let mut tracker = RewardsTracker::new();
    let total = tracker.claim_all();
    if !total.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_pending_none() -> TestResult {
    let tracker = RewardsTracker::new();
    if !tracker.pending().is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_pending_all() -> TestResult {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    tracker.add_epoch_reward(101, 1000, 10000, &quality, NodeTier::Gold);
    let pending = tracker.pending();
    if pending.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_pending_after_claim() -> TestResult {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    tracker.add_epoch_reward(101, 1000, 10000, &quality, NodeTier::Gold);
    tracker.claim_epoch(100);
    let pending = tracker.pending();
    if pending.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_pending_count_none() -> TestResult {
    let tracker = RewardsTracker::new();
    if tracker.pending_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_pending_count_all() -> TestResult {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    tracker.add_epoch_reward(101, 1000, 10000, &quality, NodeTier::Gold);
    tracker.add_epoch_reward(102, 1000, 10000, &quality, NodeTier::Gold);
    if tracker.pending_count() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_pending_count_partial() -> TestResult {
    let mut tracker = RewardsTracker::new();
    let quality = QualityScore::perfect();
    tracker.add_epoch_reward(100, 1000, 10000, &quality, NodeTier::Gold);
    tracker.add_epoch_reward(101, 1000, 10000, &quality, NodeTier::Gold);
    tracker.add_epoch_reward(102, 1000, 10000, &quality, NodeTier::Gold);
    tracker.claim_epoch(101);
    if tracker.pending_count() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_tracker_default() -> TestResult {
    let tracker = RewardsTracker::default();
    if tracker.history_count != 0 {
        return TestResult::Fail;
    }
    if tracker.current_streak != 0 {
        return TestResult::Fail;
    }
    if !tracker.total_earned.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rewards_constants() -> TestResult {
    if MAX_REWARD_HISTORY != 30 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
