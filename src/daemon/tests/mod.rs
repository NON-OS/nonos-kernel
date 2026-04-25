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

pub mod node;
pub mod p2p;
pub mod privacy;
pub mod rewards;
pub mod staking;
pub mod state;
pub mod types;

use crate::test::framework::{TestCase, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("daemon");

    // Types tests (31 tests)
    suite.add(TestCase::new("node_status_variants", types::test_node_status_variants));
    suite.add(TestCase::new("node_tier_ordering", types::test_node_tier_ordering));
    suite.add(TestCase::new("node_tier_min_stake", types::test_node_tier_min_stake));
    suite.add(TestCase::new("node_tier_lock_days", types::test_node_tier_lock_days));
    suite.add(TestCase::new("node_tier_apy_range", types::test_node_tier_apy_range));
    suite.add(TestCase::new("node_tier_multiplier", types::test_node_tier_multiplier));
    suite
        .add(TestCase::new("node_tier_from_stake_bronze", types::test_node_tier_from_stake_bronze));
    suite
        .add(TestCase::new("node_tier_from_stake_silver", types::test_node_tier_from_stake_silver));
    suite.add(TestCase::new("node_tier_from_stake_gold", types::test_node_tier_from_stake_gold));
    suite.add(TestCase::new(
        "node_tier_from_stake_platinum",
        types::test_node_tier_from_stake_platinum,
    ));
    suite.add(TestCase::new(
        "node_tier_from_stake_diamond",
        types::test_node_tier_from_stake_diamond,
    ));
    suite.add(TestCase::new("node_tier_name", types::test_node_tier_name));
    suite.add(TestCase::new("quality_score_new", types::test_quality_score_new));
    suite.add(TestCase::new("quality_score_perfect", types::test_quality_score_perfect));
    suite
        .add(TestCase::new("quality_score_total_perfect", types::test_quality_score_total_perfect));
    suite.add(TestCase::new("quality_score_total_zero", types::test_quality_score_total_zero));
    suite.add(TestCase::new(
        "quality_score_total_weighted",
        types::test_quality_score_total_weighted,
    ));
    suite.add(TestCase::new("quality_score_default", types::test_quality_score_default));
    suite.add(TestCase::new("token_amount_zero", types::test_token_amount_zero));
    suite.add(TestCase::new("token_amount_from_nox", types::test_token_amount_from_nox));
    suite
        .add(TestCase::new("token_amount_from_nox_large", types::test_token_amount_from_nox_large));
    suite
        .add(TestCase::new("token_amount_whole_and_frac", types::test_token_amount_whole_and_frac));
    suite.add(TestCase::new("token_amount_checked_add", types::test_token_amount_checked_add));
    suite.add(TestCase::new(
        "token_amount_checked_add_mismatched_decimals",
        types::test_token_amount_checked_add_mismatched_decimals,
    ));
    suite.add(TestCase::new("token_amount_checked_sub", types::test_token_amount_checked_sub));
    suite.add(TestCase::new(
        "token_amount_checked_sub_underflow",
        types::test_token_amount_checked_sub_underflow,
    ));
    suite.add(TestCase::new(
        "token_amount_checked_sub_mismatched_decimals",
        types::test_token_amount_checked_sub_mismatched_decimals,
    ));
    suite.add(TestCase::new("token_amount_default", types::test_token_amount_default));
    suite.add(TestCase::new("connection_status_variants", types::test_connection_status_variants));
    suite.add(TestCase::new("connection_status_default", types::test_connection_status_default));
    suite.add(TestCase::new("constants", types::test_constants));

    // Node tests (26 tests)
    suite.add(TestCase::new("node_id_from_bytes", node::test_node_id_from_bytes));
    suite.add(TestCase::new("node_id_as_bytes", node::test_node_id_as_bytes));
    suite.add(TestCase::new("node_id_short_id_prefix", node::test_node_id_short_id_prefix));
    suite.add(TestCase::new("node_id_short_id_length", node::test_node_id_short_id_length));
    suite.add(TestCase::new(
        "node_id_short_id_hex_encoding",
        node::test_node_id_short_id_hex_encoding,
    ));
    suite.add(TestCase::new("node_info_generate_status", node::test_node_info_generate_status));
    suite.add(TestCase::new("node_info_generate_tier", node::test_node_info_generate_tier));
    suite.add(TestCase::new("node_info_generate_quality", node::test_node_info_generate_quality));
    suite.add(TestCase::new("node_info_generate_staked", node::test_node_info_generate_staked));
    suite.add(TestCase::new("node_info_generate_counters", node::test_node_info_generate_counters));
    suite.add(TestCase::new("node_info_generate_nickname", node::test_node_info_generate_nickname));
    suite.add(TestCase::new("node_info_set_nickname", node::test_node_info_set_nickname));
    suite.add(TestCase::new(
        "node_info_set_nickname_truncates",
        node::test_node_info_set_nickname_truncates,
    ));
    suite.add(TestCase::new(
        "node_info_set_nickname_empty",
        node::test_node_info_set_nickname_empty,
    ));
    suite.add(TestCase::new(
        "node_info_success_rate_zero_requests",
        node::test_node_info_success_rate_zero_requests,
    ));
    suite.add(TestCase::new(
        "node_info_success_rate_all_successful",
        node::test_node_info_success_rate_all_successful,
    ));
    suite.add(TestCase::new(
        "node_info_success_rate_partial",
        node::test_node_info_success_rate_partial,
    ));
    suite.add(TestCase::new("node_info_success_rate_none", node::test_node_info_success_rate_none));
    suite.add(TestCase::new(
        "node_info_update_quality_success_rate",
        node::test_node_info_update_quality_success_rate,
    ));
    suite.add(TestCase::new(
        "node_info_update_quality_uptime_full_day",
        node::test_node_info_update_quality_uptime_full_day,
    ));
    suite.add(TestCase::new(
        "node_info_update_quality_uptime_partial",
        node::test_node_info_update_quality_uptime_partial,
    ));
    suite.add(TestCase::new(
        "node_info_update_quality_uptime_more_than_day",
        node::test_node_info_update_quality_uptime_more_than_day,
    ));
    suite.add(TestCase::new("node_info_start", node::test_node_info_start));
    suite.add(TestCase::new("node_info_stop", node::test_node_info_stop));
    suite.add(TestCase::new("node_info_default", node::test_node_info_default));
    suite.add(TestCase::new("node_info_clone", node::test_node_info_clone));

    // Staking tests (37 tests)
    suite.add(TestCase::new("stake_record_new", staking::test_stake_record_new));
    suite.add(TestCase::new("stake_record_stake_bronze", staking::test_stake_record_stake_bronze));
    suite.add(TestCase::new("stake_record_stake_silver", staking::test_stake_record_stake_silver));
    suite.add(TestCase::new("stake_record_stake_gold", staking::test_stake_record_stake_gold));
    suite.add(TestCase::new(
        "stake_record_stake_platinum",
        staking::test_stake_record_stake_platinum,
    ));
    suite
        .add(TestCase::new("stake_record_stake_diamond", staking::test_stake_record_stake_diamond));
    suite.add(TestCase::new(
        "stake_record_stake_accumulates",
        staking::test_stake_record_stake_accumulates,
    ));
    suite.add(TestCase::new(
        "stake_record_can_unstake_not_locked",
        staking::test_stake_record_can_unstake_not_locked,
    ));
    suite.add(TestCase::new(
        "stake_record_can_unstake_locked_before_end",
        staking::test_stake_record_can_unstake_locked_before_end,
    ));
    suite.add(TestCase::new(
        "stake_record_can_unstake_locked_at_end",
        staking::test_stake_record_can_unstake_locked_at_end,
    ));
    suite.add(TestCase::new(
        "stake_record_can_unstake_locked_after_end",
        staking::test_stake_record_can_unstake_locked_after_end,
    ));
    suite.add(TestCase::new(
        "stake_record_unstake_success",
        staking::test_stake_record_unstake_success,
    ));
    suite.add(TestCase::new(
        "stake_record_unstake_locked",
        staking::test_stake_record_unstake_locked,
    ));
    suite.add(TestCase::new(
        "stake_record_unstake_insufficient",
        staking::test_stake_record_unstake_insufficient,
    ));
    suite.add(TestCase::new(
        "stake_record_unstake_updates_tier",
        staking::test_stake_record_unstake_updates_tier,
    ));
    suite.add(TestCase::new("stake_record_weight_zero", staking::test_stake_record_weight_zero));
    suite
        .add(TestCase::new("stake_record_weight_bronze", staking::test_stake_record_weight_bronze));
    suite.add(TestCase::new("staking_state_new", staking::test_staking_state_new));
    suite.add(TestCase::new("staking_state_deposit", staking::test_staking_state_deposit));
    suite.add(TestCase::new(
        "staking_state_deposit_multiple",
        staking::test_staking_state_deposit_multiple,
    ));
    suite.add(TestCase::new(
        "staking_state_withdraw_success",
        staking::test_staking_state_withdraw_success,
    ));
    suite.add(TestCase::new(
        "staking_state_withdraw_locked",
        staking::test_staking_state_withdraw_locked,
    ));
    suite.add(TestCase::new(
        "staking_state_claim_rewards_none",
        staking::test_staking_state_claim_rewards_none,
    ));
    suite.add(TestCase::new(
        "staking_state_claim_rewards_success",
        staking::test_staking_state_claim_rewards_success,
    ));
    suite
        .add(TestCase::new("staking_state_update_epoch", staking::test_staking_state_update_epoch));
    suite.add(TestCase::new(
        "staking_state_update_epoch_no_decrease",
        staking::test_staking_state_update_epoch_no_decrease,
    ));
    suite.add(TestCase::new("staking_state_add_rewards", staking::test_staking_state_add_rewards));
    suite
        .add(TestCase::new("staking_state_total_staked", staking::test_staking_state_total_staked));
    suite.add(TestCase::new("staking_state_tier", staking::test_staking_state_tier));
    suite.add(TestCase::new("staking_state_default", staking::test_staking_state_default));
    suite.add(TestCase::new(
        "calculate_epoch_reward_zero_weight",
        staking::test_calculate_epoch_reward_zero_weight,
    ));
    suite.add(TestCase::new(
        "calculate_epoch_reward_zero_total",
        staking::test_calculate_epoch_reward_zero_total,
    ));
    suite.add(TestCase::new(
        "calculate_epoch_reward_full_share",
        staking::test_calculate_epoch_reward_full_share,
    ));
    suite.add(TestCase::new(
        "calculate_epoch_reward_half_share",
        staking::test_calculate_epoch_reward_half_share,
    ));
    suite.add(TestCase::new(
        "calculate_epoch_emission_year_zero",
        staking::test_calculate_epoch_emission_year_zero,
    ));
    suite.add(TestCase::new(
        "calculate_epoch_emission_year_one",
        staking::test_calculate_epoch_emission_year_one,
    ));
    suite.add(TestCase::new(
        "calculate_epoch_emission_decreases_over_time",
        staking::test_calculate_epoch_emission_decreases_over_time,
    ));

    // P2P tests (25 tests)
    suite.add(TestCase::new("peer_info_empty", p2p::test_peer_info_empty));
    suite.add(TestCase::new("p2p_state_new", p2p::test_p2p_state_new));
    suite.add(TestCase::new("p2p_state_connect", p2p::test_p2p_state_connect));
    suite.add(TestCase::new("p2p_state_disconnect", p2p::test_p2p_state_disconnect));
    suite.add(TestCase::new("p2p_state_set_connected", p2p::test_p2p_state_set_connected));
    suite.add(TestCase::new("p2p_state_add_peer", p2p::test_p2p_state_add_peer));
    suite.add(TestCase::new("p2p_state_add_peer_multiple", p2p::test_p2p_state_add_peer_multiple));
    suite.add(TestCase::new("p2p_state_add_peer_max", p2p::test_p2p_state_add_peer_max));
    suite.add(TestCase::new(
        "p2p_state_add_peer_initializes_fields",
        p2p::test_p2p_state_add_peer_initializes_fields,
    ));
    suite.add(TestCase::new("p2p_state_remove_peer", p2p::test_p2p_state_remove_peer));
    suite.add(TestCase::new(
        "p2p_state_remove_peer_not_found",
        p2p::test_p2p_state_remove_peer_not_found,
    ));
    suite
        .add(TestCase::new("p2p_state_remove_peer_middle", p2p::test_p2p_state_remove_peer_middle));
    suite.add(TestCase::new("p2p_state_get_peer", p2p::test_p2p_state_get_peer));
    suite
        .add(TestCase::new("p2p_state_get_peer_not_found", p2p::test_p2p_state_get_peer_not_found));
    suite.add(TestCase::new(
        "p2p_state_connected_peers_none",
        p2p::test_p2p_state_connected_peers_none,
    ));
    suite.add(TestCase::new(
        "p2p_state_connected_peers_some",
        p2p::test_p2p_state_connected_peers_some,
    ));
    suite.add(TestCase::new("p2p_state_enable_mixing", p2p::test_p2p_state_enable_mixing));
    suite.add(TestCase::new("p2p_state_disable_mixing", p2p::test_p2p_state_disable_mixing));
    suite.add(TestCase::new("p2p_state_set_cache_size", p2p::test_p2p_state_set_cache_size));
    suite
        .add(TestCase::new("p2p_state_set_cache_size_max", p2p::test_p2p_state_set_cache_size_max));
    suite.add(TestCase::new(
        "p2p_state_set_cache_size_zero",
        p2p::test_p2p_state_set_cache_size_zero,
    ));
    suite.add(TestCase::new("p2p_state_default", p2p::test_p2p_state_default));
    suite.add(TestCase::new("mixer_stats_new", p2p::test_mixer_stats_new));
    suite.add(TestCase::new("mixer_stats_default", p2p::test_mixer_stats_default));
    suite.add(TestCase::new("p2p_constants", p2p::test_p2p_constants));

    // Privacy tests (28 tests)
    suite.add(TestCase::new("zk_identity_empty", privacy::test_zk_identity_empty));
    suite.add(TestCase::new("zk_identity_generate", privacy::test_zk_identity_generate));
    suite.add(TestCase::new(
        "zk_identity_generate_unique",
        privacy::test_zk_identity_generate_unique,
    ));
    suite.add(TestCase::new(
        "zk_identity_short_id_length",
        privacy::test_zk_identity_short_id_length,
    ));
    suite.add(TestCase::new("zk_identity_short_id_hex", privacy::test_zk_identity_short_id_hex));
    suite.add(TestCase::new("privacy_state_new", privacy::test_privacy_state_new));
    suite.add(TestCase::new(
        "privacy_state_create_identity",
        privacy::test_privacy_state_create_identity,
    ));
    suite.add(TestCase::new(
        "privacy_state_create_identity_multiple",
        privacy::test_privacy_state_create_identity_multiple,
    ));
    suite.add(TestCase::new(
        "privacy_state_create_identity_max",
        privacy::test_privacy_state_create_identity_max,
    ));
    suite.add(TestCase::new(
        "privacy_state_create_identity_sets_active",
        privacy::test_privacy_state_create_identity_sets_active,
    ));
    suite.add(TestCase::new(
        "privacy_state_switch_identity",
        privacy::test_privacy_state_switch_identity,
    ));
    suite.add(TestCase::new(
        "privacy_state_switch_identity_invalid_index",
        privacy::test_privacy_state_switch_identity_invalid_index,
    ));
    suite.add(TestCase::new(
        "privacy_state_switch_identity_inactive",
        privacy::test_privacy_state_switch_identity_inactive,
    ));
    suite.add(TestCase::new(
        "privacy_state_deactivate_identity",
        privacy::test_privacy_state_deactivate_identity,
    ));
    suite.add(TestCase::new(
        "privacy_state_deactivate_identity_invalid",
        privacy::test_privacy_state_deactivate_identity_invalid,
    ));
    suite.add(TestCase::new(
        "privacy_state_get_active_none",
        privacy::test_privacy_state_get_active_none,
    ));
    suite.add(TestCase::new(
        "privacy_state_get_active_some",
        privacy::test_privacy_state_get_active_some,
    ));
    suite.add(TestCase::new(
        "privacy_state_active_count_none",
        privacy::test_privacy_state_active_count_none,
    ));
    suite.add(TestCase::new(
        "privacy_state_active_count_all",
        privacy::test_privacy_state_active_count_all,
    ));
    suite.add(TestCase::new(
        "privacy_state_active_count_partial",
        privacy::test_privacy_state_active_count_partial,
    ));
    suite.add(TestCase::new(
        "privacy_state_enable_stealth",
        privacy::test_privacy_state_enable_stealth,
    ));
    suite.add(TestCase::new(
        "privacy_state_disable_stealth",
        privacy::test_privacy_state_disable_stealth,
    ));
    suite.add(TestCase::new(
        "privacy_state_set_fingerprint_protection_on",
        privacy::test_privacy_state_set_fingerprint_protection_on,
    ));
    suite.add(TestCase::new(
        "privacy_state_set_fingerprint_protection_off",
        privacy::test_privacy_state_set_fingerprint_protection_off,
    ));
    suite.add(TestCase::new(
        "privacy_state_set_request_padding_on",
        privacy::test_privacy_state_set_request_padding_on,
    ));
    suite.add(TestCase::new(
        "privacy_state_set_request_padding_off",
        privacy::test_privacy_state_set_request_padding_off,
    ));
    suite.add(TestCase::new("privacy_state_default", privacy::test_privacy_state_default));
    suite.add(TestCase::new("privacy_constants", privacy::test_privacy_constants));

    // Rewards tests (31 tests)
    suite.add(TestCase::new("epoch_reward_empty", rewards::test_epoch_reward_empty));
    suite.add(TestCase::new("rewards_tracker_new", rewards::test_rewards_tracker_new));
    suite.add(TestCase::new(
        "rewards_tracker_add_epoch_reward",
        rewards::test_rewards_tracker_add_epoch_reward,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_add_epoch_reward_updates_history",
        rewards::test_rewards_tracker_add_epoch_reward_updates_history,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_add_epoch_reward_quality_bonus_high",
        rewards::test_rewards_tracker_add_epoch_reward_quality_bonus_high,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_add_epoch_reward_quality_bonus_90",
        rewards::test_rewards_tracker_add_epoch_reward_quality_bonus_90,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_add_epoch_reward_quality_bonus_80",
        rewards::test_rewards_tracker_add_epoch_reward_quality_bonus_80,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_add_epoch_reward_quality_bonus_70",
        rewards::test_rewards_tracker_add_epoch_reward_quality_bonus_70,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_add_epoch_reward_quality_bonus_low",
        rewards::test_rewards_tracker_add_epoch_reward_quality_bonus_low,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_streak_bonus_30_days",
        rewards::test_rewards_tracker_streak_bonus_30_days,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_streak_bonus_14_days",
        rewards::test_rewards_tracker_streak_bonus_14_days,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_streak_bonus_7_days",
        rewards::test_rewards_tracker_streak_bonus_7_days,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_streak_bonus_none",
        rewards::test_rewards_tracker_streak_bonus_none,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_streak_increments",
        rewards::test_rewards_tracker_streak_increments,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_streak_resets_on_low_quality",
        rewards::test_rewards_tracker_streak_resets_on_low_quality,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_best_streak_updates",
        rewards::test_rewards_tracker_best_streak_updates,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_history_rotation",
        rewards::test_rewards_tracker_history_rotation,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_claim_epoch",
        rewards::test_rewards_tracker_claim_epoch,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_claim_epoch_not_found",
        rewards::test_rewards_tracker_claim_epoch_not_found,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_claim_epoch_already_claimed",
        rewards::test_rewards_tracker_claim_epoch_already_claimed,
    ));
    suite.add(TestCase::new("rewards_tracker_claim_all", rewards::test_rewards_tracker_claim_all));
    suite.add(TestCase::new(
        "rewards_tracker_claim_all_partial",
        rewards::test_rewards_tracker_claim_all_partial,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_claim_all_empty",
        rewards::test_rewards_tracker_claim_all_empty,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_pending_none",
        rewards::test_rewards_tracker_pending_none,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_pending_all",
        rewards::test_rewards_tracker_pending_all,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_pending_after_claim",
        rewards::test_rewards_tracker_pending_after_claim,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_pending_count_none",
        rewards::test_rewards_tracker_pending_count_none,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_pending_count_all",
        rewards::test_rewards_tracker_pending_count_all,
    ));
    suite.add(TestCase::new(
        "rewards_tracker_pending_count_partial",
        rewards::test_rewards_tracker_pending_count_partial,
    ));
    suite.add(TestCase::new("rewards_tracker_default", rewards::test_rewards_tracker_default));
    suite.add(TestCase::new("rewards_constants", rewards::test_rewards_constants));

    // State tests (4 tests)
    suite.add(TestCase::new("daemon_state_new", state::test_daemon_state_new));
    suite.add(TestCase::new("daemon_state_new_staking", state::test_daemon_state_new_staking));
    suite.add(TestCase::new("daemon_state_new_p2p", state::test_daemon_state_new_p2p));
    suite.add(TestCase::new("daemon_state_new_privacy", state::test_daemon_state_new_privacy));

    suite.run()
}
