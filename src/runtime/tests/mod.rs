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

mod capsule;
mod capsule_store;
mod isolation;
mod service;
mod stats;
mod supervisor;
mod zerostate;

use crate::test::framework::{TestCase, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("runtime");

    // Capsule tests (54)
    suite.add(TestCase::new("capsule_id_get", capsule::test_capsule_id_get));
    suite.add(TestCase::new("capsule_id_get_zero", capsule::test_capsule_id_get_zero));
    suite.add(TestCase::new("capsule_id_get_max", capsule::test_capsule_id_get_max));
    suite.add(TestCase::new("capsule_id_equality", capsule::test_capsule_id_equality));
    suite.add(TestCase::new("capsule_id_ordering", capsule::test_capsule_id_ordering));
    suite.add(TestCase::new("capsule_id_ordering_equal", capsule::test_capsule_id_ordering_equal));
    suite.add(TestCase::new("capsule_id_clone", capsule::test_capsule_id_clone));
    suite.add(TestCase::new("capsule_id_copy", capsule::test_capsule_id_copy));
    suite.add(TestCase::new("capsule_id_debug", capsule::test_capsule_id_debug));
    suite.add(TestCase::new("capsule_id_partial_ord", capsule::test_capsule_id_partial_ord));
    suite.add(TestCase::new("capsule_id_ord", capsule::test_capsule_id_ord));
    suite
        .add(TestCase::new("next_capsule_id_increments", capsule::test_next_capsule_id_increments));
    suite.add(TestCase::new("next_capsule_id_unique", capsule::test_next_capsule_id_unique));
    suite.add(TestCase::new("capsule_state_stopped", capsule::test_capsule_state_stopped));
    suite.add(TestCase::new("capsule_state_running", capsule::test_capsule_state_running));
    suite.add(TestCase::new("capsule_state_degraded", capsule::test_capsule_state_degraded));
    suite.add(TestCase::new("capsule_state_equality", capsule::test_capsule_state_equality));
    suite.add(TestCase::new("capsule_state_inequality", capsule::test_capsule_state_inequality));
    suite.add(TestCase::new("capsule_state_clone", capsule::test_capsule_state_clone));
    suite.add(TestCase::new("capsule_state_copy", capsule::test_capsule_state_copy));
    suite.add(TestCase::new("capsule_state_debug", capsule::test_capsule_state_debug));
    suite.add(TestCase::new(
        "capsule_state_all_variants_debug",
        capsule::test_capsule_state_all_variants_debug,
    ));
    suite.add(TestCase::new("capsule_quotas_default", capsule::test_capsule_quotas_default));
    suite.add(TestCase::new(
        "capsule_quotas_default_inbox_capacity",
        capsule::test_capsule_quotas_default_inbox_capacity,
    ));
    suite.add(TestCase::new(
        "capsule_quotas_default_max_msg_bytes",
        capsule::test_capsule_quotas_default_max_msg_bytes,
    ));
    suite.add(TestCase::new(
        "capsule_quotas_default_max_bytes_per_sec",
        capsule::test_capsule_quotas_default_max_bytes_per_sec,
    ));
    suite.add(TestCase::new(
        "capsule_quotas_default_heartbeat_interval",
        capsule::test_capsule_quotas_default_heartbeat_interval,
    ));
    suite.add(TestCase::new("capsule_quotas_custom", capsule::test_capsule_quotas_custom));
    suite.add(TestCase::new("capsule_quotas_clone", capsule::test_capsule_quotas_clone));
    suite.add(TestCase::new("capsule_quotas_debug", capsule::test_capsule_quotas_debug));
    suite
        .add(TestCase::new("capsule_quotas_zero_values", capsule::test_capsule_quotas_zero_values));
    suite.add(TestCase::new("capsule_quotas_max_values", capsule::test_capsule_quotas_max_values));
    suite.add(TestCase::new(
        "capsule_quotas_inbox_capacity_power_of_two",
        capsule::test_capsule_quotas_inbox_capacity_power_of_two,
    ));
    suite.add(TestCase::new(
        "capsule_quotas_max_msg_bytes_power_of_two",
        capsule::test_capsule_quotas_max_msg_bytes_power_of_two,
    ));
    suite.add(TestCase::new(
        "capsule_quotas_max_bytes_per_sec_power_of_two",
        capsule::test_capsule_quotas_max_bytes_per_sec_power_of_two,
    ));
    suite
        .add(TestCase::new("capsule_state_all_variants", capsule::test_capsule_state_all_variants));
    suite.add(TestCase::new("capsule_id_size", capsule::test_capsule_id_size));
    suite.add(TestCase::new("capsule_state_size", capsule::test_capsule_state_size));
    suite.add(TestCase::new("capsule_quotas_size", capsule::test_capsule_quotas_size));
    suite.add(TestCase::new("capsule_id_alignment", capsule::test_capsule_id_alignment));
    suite.add(TestCase::new("capsule_quotas_alignment", capsule::test_capsule_quotas_alignment));
    suite.add(TestCase::new(
        "capsule_id_min_max_ordering",
        capsule::test_capsule_id_min_max_ordering,
    ));
    suite.add(TestCase::new(
        "capsule_quotas_heartbeat_reasonable",
        capsule::test_capsule_quotas_heartbeat_reasonable,
    ));
    suite.add(TestCase::new(
        "capsule_quotas_inbox_reasonable",
        capsule::test_capsule_quotas_inbox_reasonable,
    ));
    suite.add(TestCase::new(
        "capsule_quotas_msg_bytes_reasonable",
        capsule::test_capsule_quotas_msg_bytes_reasonable,
    ));
    suite.add(TestCase::new(
        "capsule_quotas_bytes_per_sec_reasonable",
        capsule::test_capsule_quotas_bytes_per_sec_reasonable,
    ));
    suite.add(TestCase::new("next_capsule_id_nonzero", capsule::test_next_capsule_id_nonzero));
    suite
        .add(TestCase::new("capsule_id_from_sequential", capsule::test_capsule_id_from_sequential));
    suite.add(TestCase::new(
        "capsule_quotas_multiple_defaults",
        capsule::test_capsule_quotas_multiple_defaults,
    ));
    suite.add(TestCase::new(
        "capsule_state_stopped_not_running",
        capsule::test_capsule_state_stopped_not_running,
    ));
    suite.add(TestCase::new(
        "capsule_state_running_not_stopped",
        capsule::test_capsule_state_running_not_stopped,
    ));
    suite.add(TestCase::new(
        "capsule_state_degraded_not_others",
        capsule::test_capsule_state_degraded_not_others,
    ));
    suite.add(TestCase::new(
        "capsule_id_hash_eq_consistency",
        capsule::test_capsule_id_hash_eq_consistency,
    ));
    suite.add(TestCase::new(
        "capsule_quotas_clone_independence",
        capsule::test_capsule_quotas_clone_independence,
    ));

    // Capsule store tests (44)
    suite
        .add(TestCase::new("capsule_category_system", capsule_store::test_capsule_category_system));
    suite.add(TestCase::new(
        "capsule_category_privacy",
        capsule_store::test_capsule_category_privacy,
    ));
    suite.add(TestCase::new(
        "capsule_category_security",
        capsule_store::test_capsule_category_security,
    ));
    suite.add(TestCase::new(
        "capsule_category_network",
        capsule_store::test_capsule_category_network,
    ));
    suite.add(TestCase::new(
        "capsule_category_utility",
        capsule_store::test_capsule_category_utility,
    ));
    suite.add(TestCase::new(
        "capsule_category_development",
        capsule_store::test_capsule_category_development,
    ));
    suite.add(TestCase::new("capsule_category_media", capsule_store::test_capsule_category_media));
    suite.add(TestCase::new(
        "capsule_category_finance",
        capsule_store::test_capsule_category_finance,
    ));
    suite.add(TestCase::new(
        "capsule_category_communication",
        capsule_store::test_capsule_category_communication,
    ));
    suite.add(TestCase::new("capsule_category_clone", capsule_store::test_capsule_category_clone));
    suite.add(TestCase::new("capsule_category_copy", capsule_store::test_capsule_category_copy));
    suite.add(TestCase::new("capsule_category_debug", capsule_store::test_capsule_category_debug));
    suite.add(TestCase::new(
        "capsule_category_all_unique",
        capsule_store::test_capsule_category_all_unique,
    ));
    suite.add(TestCase::new("install_state_pending", capsule_store::test_install_state_pending));
    suite.add(TestCase::new(
        "install_state_payment_required",
        capsule_store::test_install_state_payment_required,
    ));
    suite.add(TestCase::new(
        "install_state_payment_submitted",
        capsule_store::test_install_state_payment_submitted,
    ));
    suite.add(TestCase::new(
        "install_state_payment_confirmed",
        capsule_store::test_install_state_payment_confirmed,
    ));
    suite.add(TestCase::new(
        "install_state_downloading",
        capsule_store::test_install_state_downloading,
    ));
    suite
        .add(TestCase::new("install_state_verifying", capsule_store::test_install_state_verifying));
    suite.add(TestCase::new(
        "install_state_installing",
        capsule_store::test_install_state_installing,
    ));
    suite
        .add(TestCase::new("install_state_installed", capsule_store::test_install_state_installed));
    suite.add(TestCase::new("install_state_failed", capsule_store::test_install_state_failed));
    suite.add(TestCase::new("install_state_clone", capsule_store::test_install_state_clone));
    suite.add(TestCase::new("install_state_copy", capsule_store::test_install_state_copy));
    suite.add(TestCase::new("install_state_debug", capsule_store::test_install_state_debug));
    suite.add(TestCase::new(
        "install_state_all_unique",
        capsule_store::test_install_state_all_unique,
    ));
    suite.add(TestCase::new("capsule_metadata_clone", capsule_store::test_capsule_metadata_clone));
    suite.add(TestCase::new("capsule_metadata_debug", capsule_store::test_capsule_metadata_debug));
    suite
        .add(TestCase::new("installation_task_clone", capsule_store::test_installation_task_clone));
    suite
        .add(TestCase::new("installation_task_debug", capsule_store::test_installation_task_debug));
    suite.add(TestCase::new(
        "installation_task_with_error",
        capsule_store::test_installation_task_with_error,
    ));
    suite.add(TestCase::new(
        "installation_task_with_tx_hash",
        capsule_store::test_installation_task_with_tx_hash,
    ));
    suite.add(TestCase::new("micro_fee_nox_constant", capsule_store::test_micro_fee_nox_constant));
    suite
        .add(TestCase::new("gas_price_gwei_constant", capsule_store::test_gas_price_gwei_constant));
    suite.add(TestCase::new(
        "mainnet_chain_id_constant",
        capsule_store::test_mainnet_chain_id_constant,
    ));
    suite.add(TestCase::new("format_nox_amount_zero", capsule_store::test_format_nox_amount_zero));
    suite.add(TestCase::new(
        "format_nox_amount_one_wei",
        capsule_store::test_format_nox_amount_one_wei,
    ));
    suite.add(TestCase::new(
        "format_nox_amount_one_nox",
        capsule_store::test_format_nox_amount_one_nox,
    ));
    suite.add(TestCase::new(
        "format_nox_amount_fractional",
        capsule_store::test_format_nox_amount_fractional,
    ));
    suite
        .add(TestCase::new("format_nox_amount_large", capsule_store::test_format_nox_amount_large));
    suite.add(TestCase::new(
        "format_nox_amount_micro_fee",
        capsule_store::test_format_nox_amount_micro_fee,
    ));
    suite
        .add(TestCase::new("installed_capsule_clone", capsule_store::test_installed_capsule_clone));
    suite
        .add(TestCase::new("installed_capsule_debug", capsule_store::test_installed_capsule_debug));
    suite.add(TestCase::new(
        "capsule_metadata_with_dilithium_signature",
        capsule_store::test_capsule_metadata_with_dilithium_signature,
    ));
    suite.add(TestCase::new(
        "capsule_metadata_without_dilithium_signature",
        capsule_store::test_capsule_metadata_without_dilithium_signature,
    ));
    suite.add(TestCase::new(
        "installation_task_progress_bounds",
        capsule_store::test_installation_task_progress_bounds,
    ));
    suite.add(TestCase::new(
        "capsule_metadata_size_bytes",
        capsule_store::test_capsule_metadata_size_bytes,
    ));
    suite.add(TestCase::new(
        "capsule_metadata_nox_fee",
        capsule_store::test_capsule_metadata_nox_fee,
    ));

    // Isolation tests (26)
    suite.add(TestCase::new(
        "isolation_policy_default_inbox_capacity",
        isolation::test_isolation_policy_default_inbox_capacity,
    ));
    suite.add(TestCase::new(
        "isolation_policy_default_max_msg_bytes",
        isolation::test_isolation_policy_default_max_msg_bytes,
    ));
    suite.add(TestCase::new(
        "isolation_policy_default_max_bytes_per_sec",
        isolation::test_isolation_policy_default_max_bytes_per_sec,
    ));
    suite.add(TestCase::new(
        "isolation_policy_default_heartbeat_interval_ms",
        isolation::test_isolation_policy_default_heartbeat_interval_ms,
    ));
    suite.add(TestCase::new("isolation_policy_clone", isolation::test_isolation_policy_clone));
    suite.add(TestCase::new("isolation_policy_debug", isolation::test_isolation_policy_debug));
    suite.add(TestCase::new(
        "isolation_policy_custom_inbox_capacity",
        isolation::test_isolation_policy_custom_inbox_capacity,
    ));
    suite.add(TestCase::new(
        "isolation_policy_custom_max_msg_bytes",
        isolation::test_isolation_policy_custom_max_msg_bytes,
    ));
    suite.add(TestCase::new(
        "isolation_policy_custom_max_bytes_per_sec",
        isolation::test_isolation_policy_custom_max_bytes_per_sec,
    ));
    suite.add(TestCase::new(
        "isolation_policy_custom_heartbeat_interval_ms",
        isolation::test_isolation_policy_custom_heartbeat_interval_ms,
    ));
    suite.add(TestCase::new(
        "isolation_policy_all_custom",
        isolation::test_isolation_policy_all_custom,
    ));
    suite.add(TestCase::new("isolation_state_new", isolation::test_isolation_state_new));
    suite.add(TestCase::new(
        "isolation_state_dropped_initial",
        isolation::test_isolation_state_dropped_initial,
    ));
    suite.add(TestCase::new(
        "isolation_state_status_format",
        isolation::test_isolation_state_status_format,
    ));
    suite.add(TestCase::new(
        "isolation_state_charge_message_small",
        isolation::test_isolation_state_charge_message_small,
    ));
    suite.add(TestCase::new(
        "isolation_state_charge_message_at_limit",
        isolation::test_isolation_state_charge_message_at_limit,
    ));
    suite.add(TestCase::new(
        "isolation_state_charge_message_over_limit",
        isolation::test_isolation_state_charge_message_over_limit,
    ));
    suite.add(TestCase::new(
        "isolation_state_dropped_increments_on_large_message",
        isolation::test_isolation_state_dropped_increments_on_large_message,
    ));
    suite.add(TestCase::new(
        "isolation_state_set_enforced",
        isolation::test_isolation_state_set_enforced,
    ));
    suite.add(TestCase::new(
        "isolation_state_multiple_charge_messages",
        isolation::test_isolation_state_multiple_charge_messages,
    ));
    suite.add(TestCase::new(
        "isolation_policy_megabyte_limits",
        isolation::test_isolation_policy_megabyte_limits,
    ));
    suite.add(TestCase::new(
        "isolation_state_capsule_name_static",
        isolation::test_isolation_state_capsule_name_static,
    ));
    suite.add(TestCase::new(
        "isolation_state_status_contains_capsule_name",
        isolation::test_isolation_state_status_contains_capsule_name,
    ));
    suite.add(TestCase::new(
        "isolation_state_status_contains_limit",
        isolation::test_isolation_state_status_contains_limit,
    ));
    suite.add(TestCase::new(
        "isolation_policy_zero_inbox_capacity",
        isolation::test_isolation_policy_zero_inbox_capacity,
    ));
    suite.add(TestCase::new(
        "isolation_policy_large_heartbeat_interval",
        isolation::test_isolation_policy_large_heartbeat_interval,
    ));
    suite.add(TestCase::new(
        "isolation_state_charge_zero_bytes",
        isolation::test_isolation_state_charge_zero_bytes,
    ));
    suite.add(TestCase::new(
        "isolation_state_multiple_dropped",
        isolation::test_isolation_state_multiple_dropped,
    ));

    // Service tests (17)
    suite.add(TestCase::new("service_bind_and_resolve", service::test_service_bind_and_resolve));
    suite.add(TestCase::new("service_unbind", service::test_service_unbind));
    suite.add(TestCase::new(
        "service_resolve_nonexistent",
        service::test_service_resolve_nonexistent,
    ));
    suite.add(TestCase::new("service_bind_overwrites", service::test_service_bind_overwrites));
    suite.add(TestCase::new("service_multiple_bindings", service::test_service_multiple_bindings));
    suite
        .add(TestCase::new("service_unbind_nonexistent", service::test_service_unbind_nonexistent));
    suite.add(TestCase::new(
        "service_resolve_after_unbind",
        service::test_service_resolve_after_unbind,
    ));
    suite.add(TestCase::new(
        "service_bind_same_capsule_multiple_services",
        service::test_service_bind_same_capsule_multiple_services,
    ));
    suite.add(TestCase::new("service_bind_empty_string", service::test_service_bind_empty_string));
    suite.add(TestCase::new("service_bind_long_names", service::test_service_bind_long_names));
    suite.add(TestCase::new(
        "service_resolve_returns_string",
        service::test_service_resolve_returns_string,
    ));
    suite.add(TestCase::new(
        "service_bind_special_characters",
        service::test_service_bind_special_characters,
    ));
    suite.add(TestCase::new(
        "service_unbind_partial_does_not_affect_others",
        service::test_service_unbind_partial_does_not_affect_others,
    ));
    suite.add(TestCase::new(
        "service_rebind_after_unbind",
        service::test_service_rebind_after_unbind,
    ));
    suite.add(TestCase::new(
        "service_resolve_case_sensitive",
        service::test_service_resolve_case_sensitive,
    ));
    suite.add(TestCase::new("service_numeric_names", service::test_service_numeric_names));

    // Stats tests (24)
    suite.add(TestCase::new("snapshot_debug", stats::test_snapshot_debug));
    suite.add(TestCase::new("snapshot_clone", stats::test_snapshot_clone));
    suite.add(TestCase::new("snapshot_starts_field", stats::test_snapshot_starts_field));
    suite.add(TestCase::new("snapshot_stops_field", stats::test_snapshot_stops_field));
    suite.add(TestCase::new("snapshot_restarts_field", stats::test_snapshot_restarts_field));
    suite.add(TestCase::new("snapshot_heartbeats_field", stats::test_snapshot_heartbeats_field));
    suite.add(TestCase::new("snapshot_all_zeros", stats::test_snapshot_all_zeros));
    suite.add(TestCase::new("snapshot_large_values", stats::test_snapshot_large_values));
    suite.add(TestCase::new("mark_start_increments", stats::test_mark_start_increments));
    suite.add(TestCase::new("mark_stop_increments", stats::test_mark_stop_increments));
    suite.add(TestCase::new("mark_restart_increments", stats::test_mark_restart_increments));
    suite.add(TestCase::new("mark_heartbeat_increments", stats::test_mark_heartbeat_increments));
    suite.add(TestCase::new("as_string_contains_start", stats::test_as_string_contains_start));
    suite.add(TestCase::new("as_string_contains_stop", stats::test_as_string_contains_stop));
    suite.add(TestCase::new("as_string_contains_restart", stats::test_as_string_contains_restart));
    suite.add(TestCase::new("as_string_contains_hb", stats::test_as_string_contains_hb));
    suite.add(TestCase::new("as_string_prefix", stats::test_as_string_prefix));
    suite.add(TestCase::new("multiple_mark_start", stats::test_multiple_mark_start));
    suite.add(TestCase::new("multiple_mark_stop", stats::test_multiple_mark_stop));
    suite.add(TestCase::new("multiple_mark_restart", stats::test_multiple_mark_restart));
    suite.add(TestCase::new("multiple_mark_heartbeat", stats::test_multiple_mark_heartbeat));
    suite.add(TestCase::new(
        "snapshot_returns_consistent_values",
        stats::test_snapshot_returns_consistent_values,
    ));
    suite.add(TestCase::new("as_string_format", stats::test_as_string_format));
    suite.add(TestCase::new("snapshot_debug_format", stats::test_snapshot_debug_format));

    // Supervisor tests (26)
    suite.add(TestCase::new(
        "supervisor_policy_default_restart_on_degraded",
        supervisor::test_supervisor_policy_default_restart_on_degraded,
    ));
    suite.add(TestCase::new(
        "supervisor_policy_default_restart_on_stopped",
        supervisor::test_supervisor_policy_default_restart_on_stopped,
    ));
    suite.add(TestCase::new(
        "supervisor_policy_default_restart_cooldown_ms",
        supervisor::test_supervisor_policy_default_restart_cooldown_ms,
    ));
    suite.add(TestCase::new(
        "supervisor_policy_default_max_restarts_per_minute",
        supervisor::test_supervisor_policy_default_max_restarts_per_minute,
    ));
    suite.add(TestCase::new("supervisor_policy_clone", supervisor::test_supervisor_policy_clone));
    suite.add(TestCase::new("supervisor_policy_debug", supervisor::test_supervisor_policy_debug));
    suite.add(TestCase::new(
        "supervisor_policy_custom_restart_on_degraded_false",
        supervisor::test_supervisor_policy_custom_restart_on_degraded_false,
    ));
    suite.add(TestCase::new(
        "supervisor_policy_custom_restart_on_stopped_false",
        supervisor::test_supervisor_policy_custom_restart_on_stopped_false,
    ));
    suite.add(TestCase::new(
        "supervisor_policy_custom_restart_cooldown_ms",
        supervisor::test_supervisor_policy_custom_restart_cooldown_ms,
    ));
    suite.add(TestCase::new(
        "supervisor_policy_custom_max_restarts_per_minute",
        supervisor::test_supervisor_policy_custom_max_restarts_per_minute,
    ));
    suite.add(TestCase::new(
        "supervisor_policy_all_custom",
        supervisor::test_supervisor_policy_all_custom,
    ));
    suite.add(TestCase::new(
        "supervisor_policy_zero_cooldown",
        supervisor::test_supervisor_policy_zero_cooldown,
    ));
    suite.add(TestCase::new(
        "supervisor_policy_zero_max_restarts",
        supervisor::test_supervisor_policy_zero_max_restarts,
    ));
    suite.add(TestCase::new(
        "supervisor_policy_large_cooldown",
        supervisor::test_supervisor_policy_large_cooldown,
    ));
    suite.add(TestCase::new(
        "supervisor_policy_large_max_restarts",
        supervisor::test_supervisor_policy_large_max_restarts,
    ));
    suite.add(TestCase::new(
        "supervisor_policy_both_restart_flags_true",
        supervisor::test_supervisor_policy_both_restart_flags_true,
    ));
    suite.add(TestCase::new(
        "supervisor_policy_both_restart_flags_false",
        supervisor::test_supervisor_policy_both_restart_flags_false,
    ));
    suite.add(TestCase::new(
        "supervisor_policy_mixed_restart_flags",
        supervisor::test_supervisor_policy_mixed_restart_flags,
    ));
    suite.add(TestCase::new(
        "supervisor_policy_debug_contains_fields",
        supervisor::test_supervisor_policy_debug_contains_fields,
    ));
    suite.add(TestCase::new(
        "supervisor_register_and_unregister",
        supervisor::test_supervisor_register_and_unregister,
    ));
    suite.add(TestCase::new(
        "supervisor_register_custom_policy",
        supervisor::test_supervisor_register_custom_policy,
    ));
    suite.add(TestCase::new(
        "supervisor_restart_stats_none_for_unknown",
        supervisor::test_supervisor_restart_stats_none_for_unknown,
    ));
    suite.add(TestCase::new(
        "supervisor_restart_stats_after_register",
        supervisor::test_supervisor_restart_stats_after_register,
    ));
    suite.add(TestCase::new(
        "supervisor_register_multiple",
        supervisor::test_supervisor_register_multiple,
    ));
    suite.add(TestCase::new(
        "supervisor_unregister_nonexistent",
        supervisor::test_supervisor_unregister_nonexistent,
    ));
    suite.add(TestCase::new(
        "supervisor_policy_max_values",
        supervisor::test_supervisor_policy_max_values,
    ));

    // Zerostate tests (20)
    suite.add(TestCase::new(
        "zerostate_register_capsule",
        zerostate::test_zerostate_register_capsule,
    ));
    suite.add(TestCase::new(
        "zerostate_register_capsule_with_peers",
        zerostate::test_zerostate_register_capsule_with_peers,
    ));
    suite.add(TestCase::new(
        "zerostate_register_capsule_with_custom_quotas",
        zerostate::test_zerostate_register_capsule_with_custom_quotas,
    ));
    suite.add(TestCase::new(
        "zerostate_get_capsule_by_name",
        zerostate::test_zerostate_get_capsule_by_name,
    ));
    suite.add(TestCase::new(
        "zerostate_get_capsule_by_name_nonexistent",
        zerostate::test_zerostate_get_capsule_by_name_nonexistent,
    ));
    suite.add(TestCase::new(
        "zerostate_heartbeat_for_registered",
        zerostate::test_zerostate_heartbeat_for_registered,
    ));
    suite.add(TestCase::new(
        "zerostate_heartbeat_for_nonexistent",
        zerostate::test_zerostate_heartbeat_for_nonexistent,
    ));
    suite.add(TestCase::new(
        "zerostate_poll_capsule_none_when_empty",
        zerostate::test_zerostate_poll_capsule_none_when_empty,
    ));
    suite.add(TestCase::new(
        "zerostate_poll_capsule_nonexistent",
        zerostate::test_zerostate_poll_capsule_nonexistent,
    ));
    suite.add(TestCase::new(
        "zerostate_register_multiple_capsules",
        zerostate::test_zerostate_register_multiple_capsules,
    ));
    suite.add(TestCase::new(
        "zerostate_capsule_initial_health",
        zerostate::test_zerostate_capsule_initial_health,
    ));
    suite.add(TestCase::new(
        "zerostate_monitor_once_no_panic",
        zerostate::test_zerostate_monitor_once_no_panic,
    ));
    suite.add(TestCase::new(
        "zerostate_monitor_once_multiple_calls",
        zerostate::test_zerostate_monitor_once_multiple_calls,
    ));
    suite.add(TestCase::new(
        "zerostate_capsule_ids_increasing",
        zerostate::test_zerostate_capsule_ids_increasing,
    ));
    suite.add(TestCase::new(
        "zerostate_register_with_empty_peers",
        zerostate::test_zerostate_register_with_empty_peers,
    ));
    suite.add(TestCase::new(
        "zerostate_register_with_many_peers",
        zerostate::test_zerostate_register_with_many_peers,
    ));
    suite.add(TestCase::new(
        "zerostate_capsule_name_preserved",
        zerostate::test_zerostate_capsule_name_preserved,
    ));
    suite.add(TestCase::new("zerostate_quotas_applied", zerostate::test_zerostate_quotas_applied));
    suite.add(TestCase::new(
        "zerostate_stop_capsule_not_found",
        zerostate::test_zerostate_stop_capsule_not_found,
    ));
    suite.add(TestCase::new(
        "zerostate_start_capsule_not_found",
        zerostate::test_zerostate_start_capsule_not_found,
    ));

    suite.run()
}
