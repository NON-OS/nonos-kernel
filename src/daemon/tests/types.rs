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
fn test_node_status_variants() {
    assert_eq!(NodeStatus::Stopped, NodeStatus::Stopped);
    assert_eq!(NodeStatus::Starting, NodeStatus::Starting);
    assert_eq!(NodeStatus::Running, NodeStatus::Running);
    assert_eq!(NodeStatus::Syncing, NodeStatus::Syncing);
    assert_eq!(NodeStatus::Error, NodeStatus::Error);
    assert_ne!(NodeStatus::Stopped, NodeStatus::Running);
}

#[test]
fn test_node_tier_ordering() {
    assert!(NodeTier::Bronze < NodeTier::Silver);
    assert!(NodeTier::Silver < NodeTier::Gold);
    assert!(NodeTier::Gold < NodeTier::Platinum);
    assert!(NodeTier::Platinum < NodeTier::Diamond);
}

#[test]
fn test_node_tier_min_stake() {
    assert_eq!(NodeTier::Bronze.min_stake(), 1_000);
    assert_eq!(NodeTier::Silver.min_stake(), 10_000);
    assert_eq!(NodeTier::Gold.min_stake(), 50_000);
    assert_eq!(NodeTier::Platinum.min_stake(), 200_000);
    assert_eq!(NodeTier::Diamond.min_stake(), 1_000_000);
}

#[test]
fn test_node_tier_lock_days() {
    assert_eq!(NodeTier::Bronze.lock_days(), 0);
    assert_eq!(NodeTier::Silver.lock_days(), 30);
    assert_eq!(NodeTier::Gold.lock_days(), 90);
    assert_eq!(NodeTier::Platinum.lock_days(), 180);
    assert_eq!(NodeTier::Diamond.lock_days(), 365);
}

#[test]
fn test_node_tier_apy_range() {
    assert_eq!(NodeTier::Bronze.apy_range(), (5, 8));
    assert_eq!(NodeTier::Silver.apy_range(), (8, 12));
    assert_eq!(NodeTier::Gold.apy_range(), (12, 18));
    assert_eq!(NodeTier::Platinum.apy_range(), (18, 25));
    assert_eq!(NodeTier::Diamond.apy_range(), (25, 35));
}

#[test]
fn test_node_tier_multiplier() {
    assert_eq!(NodeTier::Bronze.multiplier(), 100);
    assert_eq!(NodeTier::Silver.multiplier(), 150);
    assert_eq!(NodeTier::Gold.multiplier(), 200);
    assert_eq!(NodeTier::Platinum.multiplier(), 250);
    assert_eq!(NodeTier::Diamond.multiplier(), 300);
}

#[test]
fn test_node_tier_from_stake_bronze() {
    assert_eq!(NodeTier::from_stake(0), NodeTier::Bronze);
    assert_eq!(NodeTier::from_stake(999), NodeTier::Bronze);
    assert_eq!(NodeTier::from_stake(1_000), NodeTier::Bronze);
    assert_eq!(NodeTier::from_stake(9_999), NodeTier::Bronze);
}

#[test]
fn test_node_tier_from_stake_silver() {
    assert_eq!(NodeTier::from_stake(10_000), NodeTier::Silver);
    assert_eq!(NodeTier::from_stake(49_999), NodeTier::Silver);
}

#[test]
fn test_node_tier_from_stake_gold() {
    assert_eq!(NodeTier::from_stake(50_000), NodeTier::Gold);
    assert_eq!(NodeTier::from_stake(199_999), NodeTier::Gold);
}

#[test]
fn test_node_tier_from_stake_platinum() {
    assert_eq!(NodeTier::from_stake(200_000), NodeTier::Platinum);
    assert_eq!(NodeTier::from_stake(999_999), NodeTier::Platinum);
}

#[test]
fn test_node_tier_from_stake_diamond() {
    assert_eq!(NodeTier::from_stake(1_000_000), NodeTier::Diamond);
    assert_eq!(NodeTier::from_stake(10_000_000), NodeTier::Diamond);
}

#[test]
fn test_node_tier_name() {
    assert_eq!(NodeTier::Bronze.name(), b"Bronze");
    assert_eq!(NodeTier::Silver.name(), b"Silver");
    assert_eq!(NodeTier::Gold.name(), b"Gold");
    assert_eq!(NodeTier::Platinum.name(), b"Platinum");
    assert_eq!(NodeTier::Diamond.name(), b"Diamond");
}

#[test]
fn test_quality_score_new() {
    let score = QualityScore::new();
    assert_eq!(score.uptime, 0);
    assert_eq!(score.success_rate, 0);
    assert_eq!(score.latency_score, 0);
    assert_eq!(score.reliability, 0);
}

#[test]
fn test_quality_score_perfect() {
    let score = QualityScore::perfect();
    assert_eq!(score.uptime, 100);
    assert_eq!(score.success_rate, 100);
    assert_eq!(score.latency_score, 100);
    assert_eq!(score.reliability, 100);
}

#[test]
fn test_quality_score_total_perfect() {
    let score = QualityScore::perfect();
    assert_eq!(score.total(), 100);
}

#[test]
fn test_quality_score_total_zero() {
    let score = QualityScore::new();
    assert_eq!(score.total(), 0);
}

#[test]
fn test_quality_score_total_weighted() {
    let score = QualityScore {
        uptime: 100,
        success_rate: 0,
        latency_score: 0,
        reliability: 0,
    };
    assert_eq!(score.total(), 30);

    let score = QualityScore {
        uptime: 0,
        success_rate: 100,
        latency_score: 0,
        reliability: 0,
    };
    assert_eq!(score.total(), 35);

    let score = QualityScore {
        uptime: 0,
        success_rate: 0,
        latency_score: 100,
        reliability: 0,
    };
    assert_eq!(score.total(), 20);

    let score = QualityScore {
        uptime: 0,
        success_rate: 0,
        latency_score: 0,
        reliability: 100,
    };
    assert_eq!(score.total(), 15);
}

#[test]
fn test_quality_score_default() {
    let score = QualityScore::default();
    assert_eq!(score.uptime, 0);
    assert_eq!(score.total(), 0);
}

#[test]
fn test_token_amount_zero() {
    let amount = TokenAmount::zero();
    assert_eq!(amount.raw, 0);
    assert_eq!(amount.decimals, NOX_DECIMALS);
    assert!(amount.is_zero());
}

#[test]
fn test_token_amount_from_nox() {
    let amount = TokenAmount::from_nox(1);
    assert_eq!(amount.whole(), 1);
    assert_eq!(amount.frac(), 0);
    assert!(!amount.is_zero());
}

#[test]
fn test_token_amount_from_nox_large() {
    let amount = TokenAmount::from_nox(1_000_000);
    assert_eq!(amount.whole(), 1_000_000);
    assert_eq!(amount.frac(), 0);
}

#[test]
fn test_token_amount_whole_and_frac() {
    let amount = TokenAmount {
        raw: 1_500_000_000_000_000_000,
        decimals: NOX_DECIMALS,
    };
    assert_eq!(amount.whole(), 1);
    assert_eq!(amount.frac(), 500_000_000_000_000_000);
}

#[test]
fn test_token_amount_checked_add() {
    let a = TokenAmount::from_nox(100);
    let b = TokenAmount::from_nox(50);
    let result = a.checked_add(&b);
    assert!(result.is_some());
    assert_eq!(result.unwrap().whole(), 150);
}

#[test]
fn test_token_amount_checked_add_mismatched_decimals() {
    let a = TokenAmount::from_nox(100);
    let b = TokenAmount { raw: 50, decimals: 8 };
    let result = a.checked_add(&b);
    assert!(result.is_none());
}

#[test]
fn test_token_amount_checked_sub() {
    let a = TokenAmount::from_nox(100);
    let b = TokenAmount::from_nox(50);
    let result = a.checked_sub(&b);
    assert!(result.is_some());
    assert_eq!(result.unwrap().whole(), 50);
}

#[test]
fn test_token_amount_checked_sub_underflow() {
    let a = TokenAmount::from_nox(50);
    let b = TokenAmount::from_nox(100);
    let result = a.checked_sub(&b);
    assert!(result.is_none());
}

#[test]
fn test_token_amount_checked_sub_mismatched_decimals() {
    let a = TokenAmount::from_nox(100);
    let b = TokenAmount { raw: 50, decimals: 8 };
    let result = a.checked_sub(&b);
    assert!(result.is_none());
}

#[test]
fn test_token_amount_default() {
    let amount = TokenAmount::default();
    assert!(amount.is_zero());
    assert_eq!(amount.decimals, NOX_DECIMALS);
}

#[test]
fn test_connection_status_variants() {
    assert_eq!(ConnectionStatus::Disconnected, ConnectionStatus::Disconnected);
    assert_eq!(ConnectionStatus::Connecting, ConnectionStatus::Connecting);
    assert_eq!(ConnectionStatus::Bootstrapping, ConnectionStatus::Bootstrapping);
    assert_eq!(ConnectionStatus::Connected, ConnectionStatus::Connected);
    assert_eq!(ConnectionStatus::Error, ConnectionStatus::Error);
}

#[test]
fn test_connection_status_default() {
    let status = ConnectionStatus::default();
    assert_eq!(status, ConnectionStatus::Disconnected);
}

#[test]
fn test_constants() {
    assert_eq!(NOX_DECIMALS, 18);
    assert_eq!(NOX_TOTAL_SUPPLY, 800_000_000);
    assert_eq!(NOX_STAKING_POOL, 32_000_000);
    assert_eq!(EPOCH_DURATION_SECS, 86_400);
}
