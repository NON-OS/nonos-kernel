// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

pub mod channel_tests;
pub mod inbox_tests;
pub mod message_tests;
pub mod nonos_ipc_tests;
pub mod pipe_tests;
pub mod policy_tests;

use crate::test::framework::{TestCase, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("ipc");

    // Channel tests (45)
    suite.add(TestCase::new("ipc_message_creation", channel_tests::test_ipc_message_creation));
    suite.add(TestCase::new(
        "ipc_message_empty_payload",
        channel_tests::test_ipc_message_empty_payload,
    ));
    suite.add(TestCase::new(
        "ipc_message_payload_size",
        channel_tests::test_ipc_message_payload_size,
    ));
    suite.add(TestCase::new(
        "ipc_message_validate_integrity",
        channel_tests::test_ipc_message_validate_integrity,
    ));
    suite.add(TestCase::new(
        "ipc_message_with_timestamp",
        channel_tests::test_ipc_message_with_timestamp,
    ));
    suite.add(TestCase::new(
        "ipc_message_size_limit_exceeded",
        channel_tests::test_ipc_message_size_limit_exceeded,
    ));
    suite.add(TestCase::new(
        "ipc_message_size_limit_at_boundary",
        channel_tests::test_ipc_message_size_limit_at_boundary,
    ));
    suite.add(TestCase::new("ipc_message_display", channel_tests::test_ipc_message_display));
    suite.add(TestCase::new("ipc_message_clone", channel_tests::test_ipc_message_clone));
    suite.add(TestCase::new("ipc_channel_key", channel_tests::test_ipc_channel_key));
    suite.add(TestCase::new("ipc_channel_debug", channel_tests::test_ipc_channel_debug));
    suite.add(TestCase::new("ipc_channel_copy", channel_tests::test_ipc_channel_copy));
    suite.add(TestCase::new(
        "compute_channel_key_consistency",
        channel_tests::test_compute_channel_key_consistency,
    ));
    suite.add(TestCase::new(
        "compute_channel_key_different_endpoints",
        channel_tests::test_compute_channel_key_different_endpoints,
    ));
    suite.add(TestCase::new(
        "compute_channel_key_order_matters",
        channel_tests::test_compute_channel_key_order_matters,
    ));
    suite.add(TestCase::new(
        "compute_checksum_consistency",
        channel_tests::test_compute_checksum_consistency,
    ));
    suite.add(TestCase::new(
        "compute_checksum_different_data",
        channel_tests::test_compute_checksum_different_data,
    ));
    suite.add(TestCase::new(
        "compute_checksum_different_timestamp",
        channel_tests::test_compute_checksum_different_timestamp,
    ));
    suite.add(TestCase::new(
        "init_ipc_secret_idempotent",
        channel_tests::test_init_ipc_secret_idempotent,
    ));
    suite.add(TestCase::new("ipc_bus_new", channel_tests::test_ipc_bus_new));
    suite.add(TestCase::new("ipc_bus_channel_exists", channel_tests::test_ipc_bus_channel_exists));
    suite.add(TestCase::new(
        "ipc_bus_open_channel_idempotent",
        channel_tests::test_ipc_bus_open_channel_idempotent,
    ));
    suite.add(TestCase::new(
        "ipc_bus_open_channel_empty_endpoints",
        channel_tests::test_ipc_bus_open_channel_empty_endpoints,
    ));
    suite.add(TestCase::new("ipc_bus_find_channel", channel_tests::test_ipc_bus_find_channel));
    suite.add(TestCase::new(
        "ipc_bus_enqueue_and_dequeue",
        channel_tests::test_ipc_bus_enqueue_and_dequeue,
    ));
    suite.add(TestCase::new("ipc_bus_list_routes", channel_tests::test_ipc_bus_list_routes));
    suite.add(TestCase::new("ipc_bus_remove_channel", channel_tests::test_ipc_bus_remove_channel));
    suite.add(TestCase::new(
        "ipc_bus_remove_all_channels_for_module",
        channel_tests::test_ipc_bus_remove_all_channels_for_module,
    ));
    suite.add(TestCase::new("ipc_bus_get_stats", channel_tests::test_ipc_bus_get_stats));
    suite.add(TestCase::new(
        "bus_stats_snapshot_display",
        channel_tests::test_bus_stats_snapshot_display,
    ));
    suite
        .add(TestCase::new("channel_error_not_found", channel_tests::test_channel_error_not_found));
    suite.add(TestCase::new(
        "channel_error_queue_full",
        channel_tests::test_channel_error_queue_full,
    ));
    suite.add(TestCase::new(
        "channel_error_message_too_large",
        channel_tests::test_channel_error_message_too_large,
    ));
    suite.add(TestCase::new(
        "channel_error_already_exists",
        channel_tests::test_channel_error_already_exists,
    ));
    suite.add(TestCase::new(
        "channel_error_invalid_endpoints",
        channel_tests::test_channel_error_invalid_endpoints,
    ));
    suite.add(TestCase::new(
        "channel_error_integrity_check_failed",
        channel_tests::test_channel_error_integrity_check_failed,
    ));
    suite.add(TestCase::new("channel_error_equality", channel_tests::test_channel_error_equality));
    suite.add(TestCase::new(
        "default_max_queue_constant",
        channel_tests::test_default_max_queue_constant,
    ));
    suite.add(TestCase::new(
        "default_msg_timeout_constant",
        channel_tests::test_default_msg_timeout_constant,
    ));
    suite.add(TestCase::new(
        "max_message_size_constant",
        channel_tests::test_max_message_size_constant,
    ));
    suite.add(TestCase::new("global_ipc_bus_exists", channel_tests::test_global_ipc_bus_exists));
    suite.add(TestCase::new(
        "ipc_bus_find_dead_channels_empty",
        channel_tests::test_ipc_bus_find_dead_channels_empty,
    ));
    suite.add(TestCase::new(
        "ipc_bus_get_timed_out_messages_empty",
        channel_tests::test_ipc_bus_get_timed_out_messages_empty,
    ));
    suite.add(TestCase::new(
        "ipc_bus_get_next_message_empty",
        channel_tests::test_ipc_bus_get_next_message_empty,
    ));
    suite.add(TestCase::new(
        "ipc_bus_remove_channel_out_of_bounds",
        channel_tests::test_ipc_bus_remove_channel_out_of_bounds,
    ));

    // Inbox tests (30)
    suite.add(TestCase::new("inbox_error_not_found", inbox_tests::test_inbox_error_not_found));
    suite.add(TestCase::new("inbox_error_full", inbox_tests::test_inbox_error_full));
    suite.add(TestCase::new("inbox_error_timeout", inbox_tests::test_inbox_error_timeout));
    suite.add(TestCase::new(
        "inbox_error_invalid_capacity",
        inbox_tests::test_inbox_error_invalid_capacity,
    ));
    suite.add(TestCase::new(
        "inbox_error_empty_module_name",
        inbox_tests::test_inbox_error_empty_module_name,
    ));
    suite.add(TestCase::new(
        "inbox_error_display_not_found",
        inbox_tests::test_inbox_error_display_not_found,
    ));
    suite
        .add(TestCase::new("inbox_error_display_full", inbox_tests::test_inbox_error_display_full));
    suite.add(TestCase::new(
        "inbox_error_display_timeout",
        inbox_tests::test_inbox_error_display_timeout,
    ));
    suite.add(TestCase::new(
        "inbox_error_display_invalid_capacity",
        inbox_tests::test_inbox_error_display_invalid_capacity,
    ));
    suite.add(TestCase::new(
        "inbox_error_display_empty_module_name",
        inbox_tests::test_inbox_error_display_empty_module_name,
    ));
    suite.add(TestCase::new("inbox_error_clone", inbox_tests::test_inbox_error_clone));
    suite.add(TestCase::new("inbox_error_equality", inbox_tests::test_inbox_error_equality));
    suite.add(TestCase::new(
        "inbox_error_different_variants",
        inbox_tests::test_inbox_error_different_variants,
    ));
    suite.add(TestCase::new("inbox_error_debug", inbox_tests::test_inbox_error_debug));
    suite.add(TestCase::new(
        "inbox_error_all_variants_have_str",
        inbox_tests::test_inbox_error_all_variants_have_str,
    ));
    suite.add(TestCase::new(
        "inbox_stats_snapshot_display",
        inbox_tests::test_inbox_stats_snapshot_display,
    ));
    suite.add(TestCase::new(
        "inbox_stats_snapshot_clone",
        inbox_tests::test_inbox_stats_snapshot_clone,
    ));
    suite.add(TestCase::new(
        "inbox_stats_snapshot_copy",
        inbox_tests::test_inbox_stats_snapshot_copy,
    ));
    suite.add(TestCase::new(
        "inbox_stats_snapshot_debug",
        inbox_tests::test_inbox_stats_snapshot_debug,
    ));
    suite.add(TestCase::new(
        "inbox_stats_snapshot_empty",
        inbox_tests::test_inbox_stats_snapshot_empty,
    ));
    suite.add(TestCase::new(
        "inbox_stats_snapshot_full_utilization",
        inbox_tests::test_inbox_stats_snapshot_full_utilization,
    ));
    suite.add(TestCase::new(
        "inbox_stats_snapshot_with_drops",
        inbox_tests::test_inbox_stats_snapshot_with_drops,
    ));
    suite.add(TestCase::new(
        "inbox_stats_snapshot_large_values",
        inbox_tests::test_inbox_stats_snapshot_large_values,
    ));
    suite.add(TestCase::new(
        "inbox_error_with_special_characters",
        inbox_tests::test_inbox_error_with_special_characters,
    ));
    suite
        .add(TestCase::new("inbox_error_with_unicode", inbox_tests::test_inbox_error_with_unicode));
    suite.add(TestCase::new(
        "inbox_error_full_zero_capacity",
        inbox_tests::test_inbox_error_full_zero_capacity,
    ));
    suite.add(TestCase::new(
        "inbox_error_timeout_zero_wait",
        inbox_tests::test_inbox_error_timeout_zero_wait,
    ));
    suite.add(TestCase::new(
        "inbox_error_invalid_capacity_edge_case",
        inbox_tests::test_inbox_error_invalid_capacity_edge_case,
    ));
    suite.add(TestCase::new(
        "inbox_stats_pending_messages",
        inbox_tests::test_inbox_stats_pending_messages,
    ));
    suite.add(TestCase::new(
        "inbox_stats_display_format",
        inbox_tests::test_inbox_stats_display_format,
    ));

    // Message tests (78)
    suite.add(TestCase::new("security_level_none", message_tests::test_security_level_none));
    suite.add(TestCase::new("security_level_signed", message_tests::test_security_level_signed));
    suite.add(TestCase::new(
        "security_level_encrypted",
        message_tests::test_security_level_encrypted,
    ));
    suite
        .add(TestCase::new("security_level_ordering", message_tests::test_security_level_ordering));
    suite.add(TestCase::new(
        "security_level_meets_requirement_none",
        message_tests::test_security_level_meets_requirement_none,
    ));
    suite.add(TestCase::new(
        "security_level_meets_requirement_signed",
        message_tests::test_security_level_meets_requirement_signed,
    ));
    suite.add(TestCase::new(
        "security_level_meets_requirement_encrypted",
        message_tests::test_security_level_meets_requirement_encrypted,
    ));
    suite.add(TestCase::new("security_level_default", message_tests::test_security_level_default));
    suite.add(TestCase::new("security_level_clone", message_tests::test_security_level_clone));
    suite.add(TestCase::new("security_level_copy", message_tests::test_security_level_copy));
    suite
        .add(TestCase::new("security_level_equality", message_tests::test_security_level_equality));
    suite.add(TestCase::new("security_level_debug", message_tests::test_security_level_debug));
    suite.add(TestCase::new("security_level_display", message_tests::test_security_level_display));
    suite.add(TestCase::new("message_type_data", message_tests::test_message_type_data));
    suite.add(TestCase::new("message_type_control", message_tests::test_message_type_control));
    suite.add(TestCase::new("message_type_timeout", message_tests::test_message_type_timeout));
    suite.add(TestCase::new(
        "message_type_delivery_failure",
        message_tests::test_message_type_delivery_failure,
    ));
    suite.add(TestCase::new(
        "message_type_capability_result",
        message_tests::test_message_type_capability_result,
    ));
    suite.add(TestCase::new("message_type_error", message_tests::test_message_type_error));
    suite.add(TestCase::new("message_type_ack", message_tests::test_message_type_ack));
    suite.add(TestCase::new("message_type_request", message_tests::test_message_type_request));
    suite.add(TestCase::new("message_type_response", message_tests::test_message_type_response));
    suite.add(TestCase::new("message_type_default", message_tests::test_message_type_default));
    suite.add(TestCase::new("message_type_clone", message_tests::test_message_type_clone));
    suite.add(TestCase::new("message_type_copy", message_tests::test_message_type_copy));
    suite.add(TestCase::new("message_type_equality", message_tests::test_message_type_equality));
    suite.add(TestCase::new("message_type_debug", message_tests::test_message_type_debug));
    suite.add(TestCase::new("message_type_display", message_tests::test_message_type_display));
    suite.add(TestCase::new(
        "message_error_empty_source",
        message_tests::test_message_error_empty_source,
    ));
    suite.add(TestCase::new(
        "message_error_empty_destination",
        message_tests::test_message_error_empty_destination,
    ));
    suite.add(TestCase::new(
        "message_error_payload_too_large",
        message_tests::test_message_error_payload_too_large,
    ));
    suite.add(TestCase::new(
        "message_error_invalid_session_id",
        message_tests::test_message_error_invalid_session_id,
    ));
    suite.add(TestCase::new(
        "message_error_security_level_mismatch",
        message_tests::test_message_error_security_level_mismatch,
    ));
    suite.add(TestCase::new(
        "message_error_display_empty_source",
        message_tests::test_message_error_display_empty_source,
    ));
    suite.add(TestCase::new(
        "message_error_display_payload_too_large",
        message_tests::test_message_error_display_payload_too_large,
    ));
    suite.add(TestCase::new(
        "message_error_display_security_mismatch",
        message_tests::test_message_error_display_security_mismatch,
    ));
    suite.add(TestCase::new("message_error_clone", message_tests::test_message_error_clone));
    suite.add(TestCase::new("message_error_equality", message_tests::test_message_error_equality));
    suite.add(TestCase::new("ipc_envelope_new", message_tests::test_ipc_envelope_new));
    suite.add(TestCase::new("ipc_envelope_len", message_tests::test_ipc_envelope_len));
    suite.add(TestCase::new("ipc_envelope_is_empty", message_tests::test_ipc_envelope_is_empty));
    suite
        .add(TestCase::new("ipc_envelope_total_size", message_tests::test_ipc_envelope_total_size));
    suite.add(TestCase::new(
        "ipc_envelope_validate_success",
        message_tests::test_ipc_envelope_validate_success,
    ));
    suite.add(TestCase::new(
        "ipc_envelope_validate_empty_source",
        message_tests::test_ipc_envelope_validate_empty_source,
    ));
    suite.add(TestCase::new(
        "ipc_envelope_validate_empty_destination",
        message_tests::test_ipc_envelope_validate_empty_destination,
    ));
    suite.add(TestCase::new("ipc_envelope_default", message_tests::test_ipc_envelope_default));
    suite.add(TestCase::new(
        "ipc_envelope_create_response",
        message_tests::test_ipc_envelope_create_response,
    ));
    suite.add(TestCase::new(
        "ipc_envelope_create_error_response",
        message_tests::test_ipc_envelope_create_error_response,
    ));
    suite
        .add(TestCase::new("ipc_envelope_create_ack", message_tests::test_ipc_envelope_create_ack));
    suite.add(TestCase::new("ipc_envelope_clone", message_tests::test_ipc_envelope_clone));
    suite.add(TestCase::new("envelope_builder_new", message_tests::test_envelope_builder_new));
    suite.add(TestCase::new(
        "envelope_builder_message_type",
        message_tests::test_envelope_builder_message_type,
    ));
    suite.add(TestCase::new("envelope_builder_data", message_tests::test_envelope_builder_data));
    suite.add(TestCase::new(
        "envelope_builder_data_from_slice",
        message_tests::test_envelope_builder_data_from_slice,
    ));
    suite.add(TestCase::new(
        "envelope_builder_session_id",
        message_tests::test_envelope_builder_session_id,
    ));
    suite.add(TestCase::new(
        "envelope_builder_security_level",
        message_tests::test_envelope_builder_security_level,
    ));
    suite.add(TestCase::new(
        "envelope_builder_chained",
        message_tests::test_envelope_builder_chained,
    ));
    suite.add(TestCase::new(
        "envelope_builder_build_validated_success",
        message_tests::test_envelope_builder_build_validated_success,
    ));
    suite.add(TestCase::new(
        "envelope_builder_build_validated_empty_source",
        message_tests::test_envelope_builder_build_validated_empty_source,
    ));
    suite.add(TestCase::new(
        "envelope_builder_build_validated_empty_dest",
        message_tests::test_envelope_builder_build_validated_empty_dest,
    ));
    suite.add(TestCase::new(
        "msg_ipc_message_with_timestamp",
        message_tests::test_ipc_message_with_timestamp,
    ));
    suite.add(TestCase::new(
        "msg_ipc_message_validate_integrity",
        message_tests::test_ipc_message_validate_integrity,
    ));
    suite.add(TestCase::new(
        "msg_ipc_message_payload_size",
        message_tests::test_ipc_message_payload_size,
    ));
    suite.add(TestCase::new("msg_ipc_message_is_empty", message_tests::test_ipc_message_is_empty));
    suite.add(TestCase::new("msg_ipc_message_display", message_tests::test_ipc_message_display));
    suite.add(TestCase::new("msg_ipc_message_clone", message_tests::test_ipc_message_clone));
    suite.add(TestCase::new(
        "max_payload_size_constant",
        message_tests::test_max_payload_size_constant,
    ));
    suite.add(TestCase::new(
        "msg_max_message_size_constant",
        message_tests::test_max_message_size_constant,
    ));
    suite.add(TestCase::new(
        "security_level_all_variants_have_str",
        message_tests::test_security_level_all_variants_have_str,
    ));
    suite.add(TestCase::new(
        "message_type_all_variants_have_str",
        message_tests::test_message_type_all_variants_have_str,
    ));
    suite.add(TestCase::new(
        "message_error_all_variants_have_str",
        message_tests::test_message_error_all_variants_have_str,
    ));
    suite.add(TestCase::new(
        "envelope_with_various_data_sizes",
        message_tests::test_envelope_with_various_data_sizes,
    ));
    suite.add(TestCase::new(
        "envelope_response_preserves_session",
        message_tests::test_envelope_response_preserves_session,
    ));
    suite.add(TestCase::new(
        "envelope_error_response_preserves_session",
        message_tests::test_envelope_error_response_preserves_session,
    ));
    suite.add(TestCase::new(
        "message_integrity_different_data",
        message_tests::test_message_integrity_different_data,
    ));
    suite.add(TestCase::new(
        "message_integrity_different_timestamps",
        message_tests::test_message_integrity_different_timestamps,
    ));
    suite.add(TestCase::new(
        "message_integrity_different_endpoints",
        message_tests::test_message_integrity_different_endpoints,
    ));

    // Policy tests (37)
    suite.add(TestCase::new("ipc_capability_send", policy_tests::test_ipc_capability_send));
    suite.add(TestCase::new("ipc_capability_receive", policy_tests::test_ipc_capability_receive));
    suite.add(TestCase::new(
        "ipc_capability_create_channel",
        policy_tests::test_ipc_capability_create_channel,
    ));
    suite.add(TestCase::new(
        "ipc_capability_kernel_access",
        policy_tests::test_ipc_capability_kernel_access,
    ));
    suite.add(TestCase::new(
        "ipc_capability_allow_unsigned",
        policy_tests::test_ipc_capability_allow_unsigned,
    ));
    suite.add(TestCase::new(
        "ipc_capability_large_messages",
        policy_tests::test_ipc_capability_large_messages,
    ));
    suite.add(TestCase::new(
        "ipc_capability_unlimited_rate",
        policy_tests::test_ipc_capability_unlimited_rate,
    ));
    suite.add(TestCase::new(
        "ipc_capability_network_access",
        policy_tests::test_ipc_capability_network_access,
    ));
    suite.add(TestCase::new(
        "ipc_capability_filesystem_access",
        policy_tests::test_ipc_capability_filesystem_access,
    ));
    suite.add(TestCase::new(
        "ipc_capability_crypto_access",
        policy_tests::test_ipc_capability_crypto_access,
    ));
    suite.add(TestCase::new(
        "ipc_capability_security_access",
        policy_tests::test_ipc_capability_security_access,
    ));
    suite.add(TestCase::new(
        "ipc_capability_broadcast",
        policy_tests::test_ipc_capability_broadcast,
    ));
    suite.add(TestCase::new("ipc_capability_clone", policy_tests::test_ipc_capability_clone));
    suite.add(TestCase::new("ipc_capability_copy", policy_tests::test_ipc_capability_copy));
    suite.add(TestCase::new("ipc_capability_equality", policy_tests::test_ipc_capability_equality));
    suite.add(TestCase::new("ipc_capability_debug", policy_tests::test_ipc_capability_debug));
    suite.add(TestCase::new(
        "ipc_capability_all_have_names",
        policy_tests::test_ipc_capability_all_have_names,
    ));
    suite.add(TestCase::new(
        "ipc_capability_unique_values",
        policy_tests::test_ipc_capability_unique_values,
    ));
    suite.add(TestCase::new(
        "ipc_capability_are_powers_of_two",
        policy_tests::test_ipc_capability_are_powers_of_two,
    ));
    suite.add(TestCase::new(
        "policy_violation_message_too_large",
        policy_tests::test_policy_violation_message_too_large,
    ));
    suite.add(TestCase::new(
        "policy_violation_destination_blocked",
        policy_tests::test_policy_violation_destination_blocked,
    ));
    suite.add(TestCase::new(
        "policy_violation_security_level_insufficient",
        policy_tests::test_policy_violation_security_level_insufficient,
    ));
    suite.add(TestCase::new(
        "policy_violation_rate_limit_exceeded",
        policy_tests::test_policy_violation_rate_limit_exceeded,
    ));
    suite.add(TestCase::new(
        "policy_violation_missing_capability",
        policy_tests::test_policy_violation_missing_capability,
    ));
    suite.add(TestCase::new(
        "policy_violation_invalid_token",
        policy_tests::test_policy_violation_invalid_token,
    ));
    suite.add(TestCase::new(
        "policy_violation_channel_creation_denied",
        policy_tests::test_policy_violation_channel_creation_denied,
    ));
    suite.add(TestCase::new("policy_violation_clone", policy_tests::test_policy_violation_clone));
    suite.add(TestCase::new(
        "policy_violation_equality",
        policy_tests::test_policy_violation_equality,
    ));
    suite.add(TestCase::new("policy_violation_debug", policy_tests::test_policy_violation_debug));
    suite.add(TestCase::new(
        "policy_violation_different_variants",
        policy_tests::test_policy_violation_different_variants,
    ));
    suite.add(TestCase::new(
        "capability_combination_example",
        policy_tests::test_capability_combination_example,
    ));
    suite.add(TestCase::new(
        "capability_check_example",
        policy_tests::test_capability_check_example,
    ));
    suite.add(TestCase::new(
        "capability_all_granted_example",
        policy_tests::test_capability_all_granted_example,
    ));
    suite.add(TestCase::new(
        "security_level_in_violation",
        policy_tests::test_security_level_in_violation,
    ));
    suite.add(TestCase::new("capability_in_violation", policy_tests::test_capability_in_violation));
    suite.add(TestCase::new(
        "policy_violation_with_empty_strings",
        policy_tests::test_policy_violation_with_empty_strings,
    ));
    suite.add(TestCase::new(
        "policy_violation_with_long_module_names",
        policy_tests::test_policy_violation_with_long_module_names,
    ));

    suite.run()
}
