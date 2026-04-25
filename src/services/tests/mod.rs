pub mod caps;
pub mod client;
pub mod integration;
pub mod protocol;
pub mod registry;
pub mod server;

use crate::test::framework::{TestCase, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("services");

    // Caps tests (40 tests)
    suite.add(TestCase::new("cap_vfs_bit_value", caps::test_cap_vfs_bit_value));
    suite.add(TestCase::new("cap_net_bit_value", caps::test_cap_net_bit_value));
    suite.add(TestCase::new("cap_display_bit_value", caps::test_cap_display_bit_value));
    suite.add(TestCase::new("cap_driver_bit_value", caps::test_cap_driver_bit_value));
    suite.add(TestCase::new("cap_crypto_bit_value", caps::test_cap_crypto_bit_value));
    suite.add(TestCase::new("cap_process_bit_value", caps::test_cap_process_bit_value));
    suite.add(TestCase::new("cap_memory_bit_value", caps::test_cap_memory_bit_value));
    suite.add(TestCase::new("cap_input_bit_value", caps::test_cap_input_bit_value));
    suite.add(TestCase::new("cap_audio_bit_value", caps::test_cap_audio_bit_value));
    suite.add(TestCase::new("cap_zk_bit_value", caps::test_cap_zk_bit_value));
    suite.add(TestCase::new("cap_gpu_bit_value", caps::test_cap_gpu_bit_value));
    suite.add(TestCase::new("cap_apps_bit_value", caps::test_cap_apps_bit_value));
    suite.add(TestCase::new("cap_agents_bit_value", caps::test_cap_agents_bit_value));
    suite.add(TestCase::new("cap_shell_bit_value", caps::test_cap_shell_bit_value));
    suite.add(TestCase::new("cap_admin_bit_value", caps::test_cap_admin_bit_value));
    suite.add(TestCase::new("cap_bits_are_powers_of_two", caps::test_cap_bits_are_powers_of_two));
    suite.add(TestCase::new("cap_bits_are_unique", caps::test_cap_bits_are_unique));
    suite.add(TestCase::new("service_cap_new", caps::test_service_cap_new));
    suite.add(TestCase::new("service_cap_with_expiry", caps::test_service_cap_with_expiry));
    suite.add(TestCase::new("service_cap_has_single_cap", caps::test_service_cap_has_single_cap));
    suite.add(TestCase::new(
        "service_cap_has_multiple_caps",
        caps::test_service_cap_has_multiple_caps,
    ));
    suite.add(TestCase::new(
        "service_cap_has_combined_caps",
        caps::test_service_cap_has_combined_caps,
    ));
    suite.add(TestCase::new(
        "service_cap_has_zero_cap_always_true",
        caps::test_service_cap_has_zero_cap_always_true,
    ));
    suite.add(TestCase::new(
        "service_cap_has_partial_caps_fails",
        caps::test_service_cap_has_partial_caps_fails,
    ));
    suite.add(TestCase::new(
        "service_cap_is_expired_zero_never_expires",
        caps::test_service_cap_is_expired_zero_never_expires,
    ));
    suite.add(TestCase::new(
        "service_cap_is_expired_before_expiry",
        caps::test_service_cap_is_expired_before_expiry,
    ));
    suite.add(TestCase::new(
        "service_cap_is_expired_after_expiry",
        caps::test_service_cap_is_expired_after_expiry,
    ));
    suite.add(TestCase::new("service_cap_clone", caps::test_service_cap_clone));
    suite.add(TestCase::new("service_cap_copy", caps::test_service_cap_copy));
    suite.add(TestCase::new("service_cap_equality", caps::test_service_cap_equality));
    suite.add(TestCase::new("service_cap_debug_format", caps::test_service_cap_debug_format));
    suite.add(TestCase::new("cap_error_variants_exist", caps::test_cap_error_variants_exist));
    suite.add(TestCase::new("cap_error_equality", caps::test_cap_error_equality));
    suite.add(TestCase::new("cap_error_clone", caps::test_cap_error_clone));
    suite.add(TestCase::new("cap_error_copy", caps::test_cap_error_copy));
    suite.add(TestCase::new("cap_error_debug_format", caps::test_cap_error_debug_format));
    suite.add(TestCase::new(
        "caps_can_be_combined_with_or",
        caps::test_caps_can_be_combined_with_or,
    ));
    suite.add(TestCase::new(
        "caps_can_be_checked_with_and",
        caps::test_caps_can_be_checked_with_and,
    ));
    suite.add(TestCase::new(
        "service_cap_with_all_standard_caps",
        caps::test_service_cap_with_all_standard_caps,
    ));
    suite.add(TestCase::new(
        "service_cap_admin_is_separate",
        caps::test_service_cap_admin_is_separate,
    ));
    suite.add(TestCase::new(
        "service_cap_zero_bits_has_nothing",
        caps::test_service_cap_zero_bits_has_nothing,
    ));
    suite.add(TestCase::new("service_cap_max_bits", caps::test_service_cap_max_bits));

    // Client tests (27 tests)
    suite.add(TestCase::new(
        "client_error_not_found_variant",
        client::test_client_error_not_found_variant,
    ));
    suite.add(TestCase::new(
        "client_error_capability_denied_variant",
        client::test_client_error_capability_denied_variant,
    ));
    suite.add(TestCase::new(
        "client_error_send_failed_variant",
        client::test_client_error_send_failed_variant,
    ));
    suite.add(TestCase::new(
        "client_error_recv_failed_variant",
        client::test_client_error_recv_failed_variant,
    ));
    suite.add(TestCase::new(
        "client_error_timeout_variant",
        client::test_client_error_timeout_variant,
    ));
    suite.add(TestCase::new(
        "client_error_remote_error_variant",
        client::test_client_error_remote_error_variant,
    ));
    suite.add(TestCase::new(
        "client_error_remote_error_various_codes",
        client::test_client_error_remote_error_various_codes,
    ));
    suite.add(TestCase::new(
        "client_error_equality_simple",
        client::test_client_error_equality_simple,
    ));
    suite.add(TestCase::new(
        "client_error_equality_remote_error",
        client::test_client_error_equality_remote_error,
    ));
    suite.add(TestCase::new("client_error_inequality", client::test_client_error_inequality));
    suite.add(TestCase::new("client_error_clone", client::test_client_error_clone));
    suite.add(TestCase::new(
        "client_error_clone_remote_error",
        client::test_client_error_clone_remote_error,
    ));
    suite.add(TestCase::new("client_error_copy", client::test_client_error_copy));
    suite.add(TestCase::new(
        "client_error_copy_remote_error",
        client::test_client_error_copy_remote_error,
    ));
    suite.add(TestCase::new(
        "client_error_debug_not_found",
        client::test_client_error_debug_not_found,
    ));
    suite.add(TestCase::new(
        "client_error_debug_capability_denied",
        client::test_client_error_debug_capability_denied,
    ));
    suite.add(TestCase::new(
        "client_error_debug_send_failed",
        client::test_client_error_debug_send_failed,
    ));
    suite.add(TestCase::new(
        "client_error_debug_recv_failed",
        client::test_client_error_debug_recv_failed,
    ));
    suite.add(TestCase::new("client_error_debug_timeout", client::test_client_error_debug_timeout));
    suite.add(TestCase::new(
        "client_error_debug_remote_error",
        client::test_client_error_debug_remote_error,
    ));
    suite.add(TestCase::new(
        "client_error_remote_error_zero",
        client::test_client_error_remote_error_zero,
    ));
    suite.add(TestCase::new(
        "client_error_remote_error_positive",
        client::test_client_error_remote_error_positive,
    ));
    suite.add(TestCase::new(
        "client_error_remote_error_min",
        client::test_client_error_remote_error_min,
    ));
    suite.add(TestCase::new(
        "client_error_remote_error_max",
        client::test_client_error_remote_error_max,
    ));
    suite.add(TestCase::new(
        "client_error_all_variants_distinct",
        client::test_client_error_all_variants_distinct,
    ));
    suite.add(TestCase::new(
        "service_client_connect_nonexistent",
        client::test_service_client_connect_nonexistent,
    ));
    suite.add(TestCase::new(
        "service_client_connect_empty_name",
        client::test_service_client_connect_empty_name,
    ));
    suite.add(TestCase::new(
        "service_client_connect_returns_not_found_for_unknown",
        client::test_service_client_connect_returns_not_found_for_unknown,
    ));

    // Protocol tests (44 tests)
    suite.add(TestCase::new("msg_version_is_one", protocol::test_msg_version_is_one));
    suite.add(TestCase::new("max_payload_is_4096", protocol::test_max_payload_is_4096));
    suite.add(TestCase::new("service_op_ping_value", protocol::test_service_op_ping_value));
    suite.add(TestCase::new("service_op_open_value", protocol::test_service_op_open_value));
    suite.add(TestCase::new("service_op_close_value", protocol::test_service_op_close_value));
    suite.add(TestCase::new("service_op_read_value", protocol::test_service_op_read_value));
    suite.add(TestCase::new("service_op_write_value", protocol::test_service_op_write_value));
    suite.add(TestCase::new("service_op_ioctl_value", protocol::test_service_op_ioctl_value));
    suite.add(TestCase::new("service_op_query_value", protocol::test_service_op_query_value));
    suite.add(TestCase::new(
        "service_op_subscribe_value",
        protocol::test_service_op_subscribe_value,
    ));
    suite.add(TestCase::new(
        "service_op_unsubscribe_value",
        protocol::test_service_op_unsubscribe_value,
    ));
    suite.add(TestCase::new(
        "service_op_values_are_sequential",
        protocol::test_service_op_values_are_sequential,
    ));
    suite.add(TestCase::new("service_op_clone", protocol::test_service_op_clone));
    suite.add(TestCase::new("service_op_copy", protocol::test_service_op_copy));
    suite.add(TestCase::new("service_op_equality", protocol::test_service_op_equality));
    suite.add(TestCase::new("service_op_debug_format", protocol::test_service_op_debug_format));
    suite.add(TestCase::new(
        "service_request_new_empty_payload",
        protocol::test_service_request_new_empty_payload,
    ));
    suite.add(TestCase::new(
        "service_request_new_with_payload",
        protocol::test_service_request_new_with_payload,
    ));
    suite.add(TestCase::new(
        "service_request_encode_minimum_length",
        protocol::test_service_request_encode_minimum_length,
    ));
    suite.add(TestCase::new(
        "service_request_encode_version_byte",
        protocol::test_service_request_encode_version_byte,
    ));
    suite.add(TestCase::new(
        "service_request_encode_reserved_byte",
        protocol::test_service_request_encode_reserved_byte,
    ));
    suite.add(TestCase::new(
        "service_request_encode_seq_bytes",
        protocol::test_service_request_encode_seq_bytes,
    ));
    suite.add(TestCase::new(
        "service_request_encode_op_bytes",
        protocol::test_service_request_encode_op_bytes,
    ));
    suite.add(TestCase::new(
        "service_request_encode_flags_bytes",
        protocol::test_service_request_encode_flags_bytes,
    ));
    suite.add(TestCase::new(
        "service_request_encode_payload_length",
        protocol::test_service_request_encode_payload_length,
    ));
    suite.add(TestCase::new(
        "service_request_encode_payload_content",
        protocol::test_service_request_encode_payload_content,
    ));
    suite.add(TestCase::new(
        "service_request_encode_total_length",
        protocol::test_service_request_encode_total_length,
    ));
    suite.add(TestCase::new("service_request_clone", protocol::test_service_request_clone));
    suite.add(TestCase::new(
        "service_request_debug_format",
        protocol::test_service_request_debug_format,
    ));
    suite.add(TestCase::new(
        "service_response_ok_empty_payload",
        protocol::test_service_response_ok_empty_payload,
    ));
    suite.add(TestCase::new(
        "service_response_ok_with_payload",
        protocol::test_service_response_ok_with_payload,
    ));
    suite.add(TestCase::new(
        "service_response_err_negative_status",
        protocol::test_service_response_err_negative_status,
    ));
    suite.add(TestCase::new(
        "service_response_err_various_codes",
        protocol::test_service_response_err_various_codes,
    ));
    suite.add(TestCase::new("service_response_clone", protocol::test_service_response_clone));
    suite.add(TestCase::new(
        "service_response_debug_format",
        protocol::test_service_response_debug_format,
    ));
    suite.add(TestCase::new(
        "service_message_request_variant",
        protocol::test_service_message_request_variant,
    ));
    suite.add(TestCase::new(
        "service_message_response_variant",
        protocol::test_service_message_response_variant,
    ));
    suite.add(TestCase::new("service_message_clone", protocol::test_service_message_clone));
    suite.add(TestCase::new(
        "service_message_debug_format",
        protocol::test_service_message_debug_format,
    ));
    suite.add(TestCase::new(
        "service_request_large_payload",
        protocol::test_service_request_large_payload,
    ));
    suite.add(TestCase::new("service_request_seq_zero", protocol::test_service_request_seq_zero));
    suite.add(TestCase::new("service_request_seq_max", protocol::test_service_request_seq_max));
    suite.add(TestCase::new(
        "service_response_positive_status",
        protocol::test_service_response_positive_status,
    ));
    suite.add(TestCase::new(
        "service_response_status_max_negative",
        protocol::test_service_response_status_max_negative,
    ));
    suite.add(TestCase::new(
        "all_service_ops_are_distinct",
        protocol::test_all_service_ops_are_distinct,
    ));

    // Registry tests (35 tests)
    suite.add(TestCase::new("max_services_constant", registry::test_max_services_constant));
    suite.add(TestCase::new("max_services_positive", registry::test_max_services_positive));
    suite.add(TestCase::new(
        "max_services_reasonable_upper_bound",
        registry::test_max_services_reasonable_upper_bound,
    ));
    suite.add(TestCase::new("service_endpoint_fields", registry::test_service_endpoint_fields));
    suite.add(TestCase::new(
        "service_endpoint_empty_name",
        registry::test_service_endpoint_empty_name,
    ));
    suite.add(TestCase::new("service_endpoint_clone", registry::test_service_endpoint_clone));
    suite.add(TestCase::new("service_endpoint_debug", registry::test_service_endpoint_debug));
    suite.add(TestCase::new("service_endpoint_max_port", registry::test_service_endpoint_max_port));
    suite.add(TestCase::new("service_endpoint_max_pid", registry::test_service_endpoint_max_pid));
    suite.add(TestCase::new("service_endpoint_max_caps", registry::test_service_endpoint_max_caps));
    suite.add(TestCase::new("reg_error_full", registry::test_reg_error_full));
    suite.add(TestCase::new("reg_error_exists", registry::test_reg_error_exists));
    suite.add(TestCase::new("reg_error_not_found", registry::test_reg_error_not_found));
    suite.add(TestCase::new(
        "reg_error_permission_denied",
        registry::test_reg_error_permission_denied,
    ));
    suite.add(TestCase::new("reg_error_equality", registry::test_reg_error_equality));
    suite.add(TestCase::new("reg_error_clone", registry::test_reg_error_clone));
    suite.add(TestCase::new("reg_error_copy", registry::test_reg_error_copy));
    suite.add(TestCase::new("reg_error_debug", registry::test_reg_error_debug));
    suite.add(TestCase::new("reg_error_all_variants", registry::test_reg_error_all_variants));
    suite.add(TestCase::new("reg_error_all_unique", registry::test_reg_error_all_unique));
    suite.add(TestCase::new(
        "list_endpoints_returns_vec",
        registry::test_list_endpoints_returns_vec,
    ));
    suite.add(TestCase::new(
        "lookup_nonexistent_service",
        registry::test_lookup_nonexistent_service,
    ));
    suite.add(TestCase::new(
        "register_endpoint_returns_result",
        registry::test_register_endpoint_returns_result,
    ));
    suite.add(TestCase::new(
        "register_endpoint_simple_does_not_panic",
        registry::test_register_endpoint_simple_does_not_panic,
    ));
    suite.add(TestCase::new("unregister_nonexistent", registry::test_unregister_nonexistent));
    suite.add(TestCase::new(
        "service_endpoint_long_name",
        registry::test_service_endpoint_long_name,
    ));
    suite.add(TestCase::new(
        "service_endpoint_with_unicode_name",
        registry::test_service_endpoint_with_unicode_name,
    ));
    suite.add(TestCase::new(
        "service_endpoint_name_with_numbers",
        registry::test_service_endpoint_name_with_numbers,
    ));
    suite.add(TestCase::new(
        "service_endpoint_name_with_underscores",
        registry::test_service_endpoint_name_with_underscores,
    ));
    suite.add(TestCase::new(
        "service_endpoint_port_zero",
        registry::test_service_endpoint_port_zero,
    ));
    suite.add(TestCase::new("service_endpoint_pid_zero", registry::test_service_endpoint_pid_zero));
    suite.add(TestCase::new(
        "service_endpoint_multiple_caps",
        registry::test_service_endpoint_multiple_caps,
    ));
    suite.add(TestCase::new("reg_error_debug_exists", registry::test_reg_error_debug_exists));
    suite.add(TestCase::new("reg_error_debug_not_found", registry::test_reg_error_debug_not_found));
    suite.add(TestCase::new(
        "reg_error_debug_permission_denied",
        registry::test_reg_error_debug_permission_denied,
    ));
    suite.add(TestCase::new(
        "service_endpoint_default_like",
        registry::test_service_endpoint_default_like,
    ));
    suite.add(TestCase::new("list_endpoints_type", registry::test_list_endpoints_type));
    suite.add(TestCase::new("lookup_service_type", registry::test_lookup_service_type));
    suite.add(TestCase::new("register_endpoint_type", registry::test_register_endpoint_type));
    suite.add(TestCase::new("unregister_endpoint_type", registry::test_unregister_endpoint_type));

    // Server tests (28 tests)
    suite.add(TestCase::new(
        "server_error_registration_failed",
        server::test_server_error_registration_failed,
    ));
    suite.add(TestCase::new("server_error_bind_failed", server::test_server_error_bind_failed));
    suite.add(TestCase::new(
        "server_error_already_running",
        server::test_server_error_already_running,
    ));
    suite.add(TestCase::new("server_error_equality", server::test_server_error_equality));
    suite.add(TestCase::new("server_error_clone", server::test_server_error_clone));
    suite.add(TestCase::new("server_error_copy", server::test_server_error_copy));
    suite.add(TestCase::new(
        "server_error_debug_registration_failed",
        server::test_server_error_debug_registration_failed,
    ));
    suite.add(TestCase::new(
        "server_error_debug_bind_failed",
        server::test_server_error_debug_bind_failed,
    ));
    suite.add(TestCase::new(
        "server_error_debug_already_running",
        server::test_server_error_debug_already_running,
    ));
    suite.add(TestCase::new("server_error_all_variants", server::test_server_error_all_variants));
    suite.add(TestCase::new("server_error_all_unique", server::test_server_error_all_unique));
    suite.add(TestCase::new("server_error_size", server::test_server_error_size));
    suite.add(TestCase::new(
        "server_error_from_registration",
        server::test_server_error_from_registration,
    ));
    suite.add(TestCase::new("server_error_from_bind", server::test_server_error_from_bind));
    suite.add(TestCase::new(
        "server_error_from_already_running",
        server::test_server_error_from_already_running,
    ));
    suite.add(TestCase::new("server_error_in_result_ok", server::test_server_error_in_result_ok));
    suite.add(TestCase::new(
        "server_error_in_result_err_registration",
        server::test_server_error_in_result_err_registration,
    ));
    suite.add(TestCase::new(
        "server_error_in_result_err_bind",
        server::test_server_error_in_result_err_bind,
    ));
    suite.add(TestCase::new(
        "server_error_in_result_err_running",
        server::test_server_error_in_result_err_running,
    ));
    suite.add(TestCase::new(
        "server_error_match_registration",
        server::test_server_error_match_registration,
    ));
    suite.add(TestCase::new("server_error_match_bind", server::test_server_error_match_bind));
    suite.add(TestCase::new("server_error_match_running", server::test_server_error_match_running));
    suite.add(TestCase::new("server_error_clone_all", server::test_server_error_clone_all));
    suite.add(TestCase::new(
        "server_error_copy_semantics",
        server::test_server_error_copy_semantics,
    ));
    suite.add(TestCase::new("server_error_in_vec", server::test_server_error_in_vec));
    suite.add(TestCase::new(
        "server_error_partial_eq_reflexive",
        server::test_server_error_partial_eq_reflexive,
    ));
    suite.add(TestCase::new(
        "server_error_partial_eq_symmetric",
        server::test_server_error_partial_eq_symmetric,
    ));
    suite.add(TestCase::new("server_error_eq_trait", server::test_server_error_eq_trait));

    // Integration tests (33 tests)
    suite.add(TestCase::new(
        "request_encode_then_parse",
        integration::test_request_encode_then_parse,
    ));
    suite.add(TestCase::new(
        "request_encode_parse_ping",
        integration::test_request_encode_parse_ping,
    ));
    suite.add(TestCase::new(
        "request_encode_parse_open",
        integration::test_request_encode_parse_open,
    ));
    suite.add(TestCase::new(
        "request_encode_parse_close",
        integration::test_request_encode_parse_close,
    ));
    suite.add(TestCase::new(
        "request_encode_parse_read",
        integration::test_request_encode_parse_read,
    ));
    suite.add(TestCase::new(
        "request_encode_parse_ioctl",
        integration::test_request_encode_parse_ioctl,
    ));
    suite.add(TestCase::new(
        "request_encode_parse_query",
        integration::test_request_encode_parse_query,
    ));
    suite.add(TestCase::new(
        "request_encode_parse_subscribe",
        integration::test_request_encode_parse_subscribe,
    ));
    suite.add(TestCase::new(
        "request_encode_parse_unsubscribe",
        integration::test_request_encode_parse_unsubscribe,
    ));
    suite.add(TestCase::new(
        "request_encode_parse_preserves_seq",
        integration::test_request_encode_parse_preserves_seq,
    ));
    suite.add(TestCase::new(
        "request_encode_parse_preserves_flags",
        integration::test_request_encode_parse_preserves_flags,
    ));
    suite.add(TestCase::new(
        "request_encode_parse_preserves_payload",
        integration::test_request_encode_parse_preserves_payload,
    ));
    suite.add(TestCase::new("response_ok_then_encode", integration::test_response_ok_then_encode));
    suite
        .add(TestCase::new("response_err_then_encode", integration::test_response_err_then_encode));
    suite.add(TestCase::new(
        "cap_check_with_service_cap",
        integration::test_cap_check_with_service_cap,
    ));
    suite.add(TestCase::new("cap_expiry_logic", integration::test_cap_expiry_logic));
    suite.add(TestCase::new(
        "service_message_roundtrip_request",
        integration::test_service_message_roundtrip_request,
    ));
    suite.add(TestCase::new(
        "service_message_roundtrip_response",
        integration::test_service_message_roundtrip_response,
    ));
    suite.add(TestCase::new(
        "all_ops_can_be_encoded_and_parsed",
        integration::test_all_ops_can_be_encoded_and_parsed,
    ));
    suite.add(TestCase::new(
        "client_error_from_response_status",
        integration::test_client_error_from_response_status,
    ));
    suite.add(TestCase::new("cap_bits_do_not_overlap", integration::test_cap_bits_do_not_overlap));
    suite.add(TestCase::new(
        "service_cap_combined_check",
        integration::test_service_cap_combined_check,
    ));
    suite
        .add(TestCase::new("error_types_are_distinct", integration::test_error_types_are_distinct));
    suite.add(TestCase::new(
        "request_with_max_payload_indicator",
        integration::test_request_with_max_payload_indicator,
    ));
    suite.add(TestCase::new(
        "service_endpoint_with_all_fields",
        integration::test_service_endpoint_with_all_fields,
    ));
    suite.add(TestCase::new("version_compatibility", integration::test_version_compatibility));
    suite.add(TestCase::new(
        "service_response_status_codes",
        integration::test_service_response_status_codes,
    ));
    suite.add(TestCase::new(
        "encode_decode_consistency",
        integration::test_encode_decode_consistency,
    ));
    suite.add(TestCase::new("max_services_bounds", integration::test_max_services_bounds));
    suite
        .add(TestCase::new("cap_admin_is_highest_bit", integration::test_cap_admin_is_highest_bit));
    suite.add(TestCase::new(
        "service_cap_no_expiry_means_never_expires",
        integration::test_service_cap_no_expiry_means_never_expires,
    ));

    suite.run()
}
