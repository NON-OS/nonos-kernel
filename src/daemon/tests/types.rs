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

pub(crate) fn test_node_status_variants() -> TestResult {
    if NodeStatus::Stopped != NodeStatus::Stopped {
        return TestResult::Fail;
    }
    if NodeStatus::Starting != NodeStatus::Starting {
        return TestResult::Fail;
    }
    if NodeStatus::Running != NodeStatus::Running {
        return TestResult::Fail;
    }
    if NodeStatus::Syncing != NodeStatus::Syncing {
        return TestResult::Fail;
    }
    if NodeStatus::Error != NodeStatus::Error {
        return TestResult::Fail;
    }
    if NodeStatus::Stopped == NodeStatus::Running {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_tier_ordering() -> TestResult {
    if !(NodeTier::Bronze < NodeTier::Silver) {
        return TestResult::Fail;
    }
    if !(NodeTier::Silver < NodeTier::Gold) {
        return TestResult::Fail;
    }
    if !(NodeTier::Gold < NodeTier::Platinum) {
        return TestResult::Fail;
    }
    if !(NodeTier::Platinum < NodeTier::Diamond) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_tier_min_stake() -> TestResult {
    if NodeTier::Bronze.min_stake() != 1_000 {
        return TestResult::Fail;
    }
    if NodeTier::Silver.min_stake() != 10_000 {
        return TestResult::Fail;
    }
    if NodeTier::Gold.min_stake() != 50_000 {
        return TestResult::Fail;
    }
    if NodeTier::Platinum.min_stake() != 200_000 {
        return TestResult::Fail;
    }
    if NodeTier::Diamond.min_stake() != 1_000_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_tier_lock_days() -> TestResult {
    if NodeTier::Bronze.lock_days() != 0 {
        return TestResult::Fail;
    }
    if NodeTier::Silver.lock_days() != 30 {
        return TestResult::Fail;
    }
    if NodeTier::Gold.lock_days() != 90 {
        return TestResult::Fail;
    }
    if NodeTier::Platinum.lock_days() != 180 {
        return TestResult::Fail;
    }
    if NodeTier::Diamond.lock_days() != 365 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_tier_apy_range() -> TestResult {
    if NodeTier::Bronze.apy_range() != (5, 8) {
        return TestResult::Fail;
    }
    if NodeTier::Silver.apy_range() != (8, 12) {
        return TestResult::Fail;
    }
    if NodeTier::Gold.apy_range() != (12, 18) {
        return TestResult::Fail;
    }
    if NodeTier::Platinum.apy_range() != (18, 25) {
        return TestResult::Fail;
    }
    if NodeTier::Diamond.apy_range() != (25, 35) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_tier_multiplier() -> TestResult {
    if NodeTier::Bronze.multiplier() != 100 {
        return TestResult::Fail;
    }
    if NodeTier::Silver.multiplier() != 150 {
        return TestResult::Fail;
    }
    if NodeTier::Gold.multiplier() != 200 {
        return TestResult::Fail;
    }
    if NodeTier::Platinum.multiplier() != 250 {
        return TestResult::Fail;
    }
    if NodeTier::Diamond.multiplier() != 300 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_tier_from_stake_bronze() -> TestResult {
    if NodeTier::from_stake(0) != NodeTier::Bronze {
        return TestResult::Fail;
    }
    if NodeTier::from_stake(999) != NodeTier::Bronze {
        return TestResult::Fail;
    }
    if NodeTier::from_stake(1_000) != NodeTier::Bronze {
        return TestResult::Fail;
    }
    if NodeTier::from_stake(9_999) != NodeTier::Bronze {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_tier_from_stake_silver() -> TestResult {
    if NodeTier::from_stake(10_000) != NodeTier::Silver {
        return TestResult::Fail;
    }
    if NodeTier::from_stake(49_999) != NodeTier::Silver {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_tier_from_stake_gold() -> TestResult {
    if NodeTier::from_stake(50_000) != NodeTier::Gold {
        return TestResult::Fail;
    }
    if NodeTier::from_stake(199_999) != NodeTier::Gold {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_tier_from_stake_platinum() -> TestResult {
    if NodeTier::from_stake(200_000) != NodeTier::Platinum {
        return TestResult::Fail;
    }
    if NodeTier::from_stake(999_999) != NodeTier::Platinum {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_tier_from_stake_diamond() -> TestResult {
    if NodeTier::from_stake(1_000_000) != NodeTier::Diamond {
        return TestResult::Fail;
    }
    if NodeTier::from_stake(10_000_000) != NodeTier::Diamond {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_tier_name() -> TestResult {
    if NodeTier::Bronze.name() != b"Bronze" {
        return TestResult::Fail;
    }
    if NodeTier::Silver.name() != b"Silver" {
        return TestResult::Fail;
    }
    if NodeTier::Gold.name() != b"Gold" {
        return TestResult::Fail;
    }
    if NodeTier::Platinum.name() != b"Platinum" {
        return TestResult::Fail;
    }
    if NodeTier::Diamond.name() != b"Diamond" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quality_score_new() -> TestResult {
    let score = QualityScore::new();
    if score.uptime != 0 {
        return TestResult::Fail;
    }
    if score.success_rate != 0 {
        return TestResult::Fail;
    }
    if score.latency_score != 0 {
        return TestResult::Fail;
    }
    if score.reliability != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quality_score_perfect() -> TestResult {
    let score = QualityScore::perfect();
    if score.uptime != 100 {
        return TestResult::Fail;
    }
    if score.success_rate != 100 {
        return TestResult::Fail;
    }
    if score.latency_score != 100 {
        return TestResult::Fail;
    }
    if score.reliability != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quality_score_total_perfect() -> TestResult {
    let score = QualityScore::perfect();
    if score.total() != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quality_score_total_zero() -> TestResult {
    let score = QualityScore::new();
    if score.total() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quality_score_total_weighted() -> TestResult {
    let score = QualityScore { uptime: 100, success_rate: 0, latency_score: 0, reliability: 0 };
    if score.total() != 30 {
        return TestResult::Fail;
    }

    let score = QualityScore { uptime: 0, success_rate: 100, latency_score: 0, reliability: 0 };
    if score.total() != 35 {
        return TestResult::Fail;
    }

    let score = QualityScore { uptime: 0, success_rate: 0, latency_score: 100, reliability: 0 };
    if score.total() != 20 {
        return TestResult::Fail;
    }

    let score = QualityScore { uptime: 0, success_rate: 0, latency_score: 0, reliability: 100 };
    if score.total() != 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quality_score_default() -> TestResult {
    let score = QualityScore::default();
    if score.uptime != 0 {
        return TestResult::Fail;
    }
    if score.total() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_token_amount_zero() -> TestResult {
    let amount = TokenAmount::zero();
    if amount.raw != 0 {
        return TestResult::Fail;
    }
    if amount.decimals != NOX_DECIMALS {
        return TestResult::Fail;
    }
    if !amount.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_token_amount_from_nox() -> TestResult {
    let amount = TokenAmount::from_nox(1);
    if amount.whole() != 1 {
        return TestResult::Fail;
    }
    if amount.frac() != 0 {
        return TestResult::Fail;
    }
    if amount.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_token_amount_from_nox_large() -> TestResult {
    let amount = TokenAmount::from_nox(1_000_000);
    if amount.whole() != 1_000_000 {
        return TestResult::Fail;
    }
    if amount.frac() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_token_amount_whole_and_frac() -> TestResult {
    let amount = TokenAmount { raw: 1_500_000_000_000_000_000, decimals: NOX_DECIMALS };
    if amount.whole() != 1 {
        return TestResult::Fail;
    }
    if amount.frac() != 500_000_000_000_000_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_token_amount_checked_add() -> TestResult {
    let a = TokenAmount::from_nox(100);
    let b = TokenAmount::from_nox(50);
    let result = a.checked_add(&b);
    if !result.is_some() {
        return TestResult::Fail;
    }
    if result.unwrap().whole() != 150 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_token_amount_checked_add_mismatched_decimals() -> TestResult {
    let a = TokenAmount::from_nox(100);
    let b = TokenAmount { raw: 50, decimals: 8 };
    let result = a.checked_add(&b);
    if !result.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_token_amount_checked_sub() -> TestResult {
    let a = TokenAmount::from_nox(100);
    let b = TokenAmount::from_nox(50);
    let result = a.checked_sub(&b);
    if !result.is_some() {
        return TestResult::Fail;
    }
    if result.unwrap().whole() != 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_token_amount_checked_sub_underflow() -> TestResult {
    let a = TokenAmount::from_nox(50);
    let b = TokenAmount::from_nox(100);
    let result = a.checked_sub(&b);
    if !result.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_token_amount_checked_sub_mismatched_decimals() -> TestResult {
    let a = TokenAmount::from_nox(100);
    let b = TokenAmount { raw: 50, decimals: 8 };
    let result = a.checked_sub(&b);
    if !result.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_token_amount_default() -> TestResult {
    let amount = TokenAmount::default();
    if !amount.is_zero() {
        return TestResult::Fail;
    }
    if amount.decimals != NOX_DECIMALS {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_connection_status_variants() -> TestResult {
    if ConnectionStatus::Disconnected != ConnectionStatus::Disconnected {
        return TestResult::Fail;
    }
    if ConnectionStatus::Connecting != ConnectionStatus::Connecting {
        return TestResult::Fail;
    }
    if ConnectionStatus::Bootstrapping != ConnectionStatus::Bootstrapping {
        return TestResult::Fail;
    }
    if ConnectionStatus::Connected != ConnectionStatus::Connected {
        return TestResult::Fail;
    }
    if ConnectionStatus::Error != ConnectionStatus::Error {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_connection_status_default() -> TestResult {
    let status = ConnectionStatus::default();
    if status != ConnectionStatus::Disconnected {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_constants() -> TestResult {
    if NOX_DECIMALS != 18 {
        return TestResult::Fail;
    }
    if NOX_TOTAL_SUPPLY != 800_000_000 {
        return TestResult::Fail;
    }
    if NOX_STAKING_POOL != 32_000_000 {
        return TestResult::Fail;
    }
    if EPOCH_DURATION_SECS != 86_400 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
