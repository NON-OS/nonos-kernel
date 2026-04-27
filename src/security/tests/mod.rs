// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Security subsystem test suite

mod audit;
mod boot;
mod constant_time;
mod crypto;
mod hardening;
mod monitoring;
mod observability;
mod policy;
mod quantum;
mod random;
mod sanitization;
mod session;
mod trusted_keys;
mod zkids;

use crate::test::framework::{TestCase, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("security");

    // Boot security tests
    suite.add(TestCase::new(
        "boot::secure_boot_policy_disabled",
        boot::test_secure_boot_policy_disabled,
    ));
    suite.add(TestCase::new(
        "boot::secure_boot_policy_permissive",
        boot::test_secure_boot_policy_permissive,
    ));
    suite.add(TestCase::new(
        "boot::secure_boot_policy_enforcing",
        boot::test_secure_boot_policy_enforcing,
    ));
    suite.add(TestCase::new(
        "boot::secure_boot_policy_strict",
        boot::test_secure_boot_policy_strict,
    ));
    suite.add(TestCase::new(
        "boot::secure_boot_policy_equality",
        boot::test_secure_boot_policy_equality,
    ));
    suite.add(TestCase::new(
        "boot::secure_boot_error_variants",
        boot::test_secure_boot_error_variants,
    ));
    suite.add(TestCase::new("boot::boot_measurements_new", boot::test_boot_measurements_new));
    suite.add(TestCase::new(
        "boot::boot_measurements_getters",
        boot::test_boot_measurements_getters,
    ));
    suite.add(TestCase::new(
        "boot::boot_measurements_signature_state",
        boot::test_boot_measurements_signature_state,
    ));
    suite.add(TestCase::new(
        "boot::boot_measurements_pcr_values",
        boot::test_boot_measurements_pcr_values,
    ));
    suite.add(TestCase::new(
        "boot::boot_measurements_timestamp",
        boot::test_boot_measurements_timestamp,
    ));
    suite.add(TestCase::new(
        "boot::boot_measurements_chain_verified",
        boot::test_boot_measurements_chain_verified,
    ));
    suite.add(TestCase::new("boot::trusted_boot_keys_new", boot::test_trusted_boot_keys_new));
    suite.add(TestCase::new(
        "boot::trusted_boot_keys_getters",
        boot::test_trusted_boot_keys_getters,
    ));
    suite.add(TestCase::new(
        "boot::trusted_boot_keys_revocation_check",
        boot::test_trusted_boot_keys_revocation_check,
    ));
    suite.add(TestCase::new(
        "boot::trusted_boot_keys_rotation_count",
        boot::test_trusted_boot_keys_rotation_count,
    ));
    suite.add(TestCase::new(
        "boot::trusted_boot_keys_total_count",
        boot::test_trusted_boot_keys_total_count,
    ));
    suite.add(TestCase::new(
        "boot::attestation_report_fields",
        boot::test_attestation_report_fields,
    ));
    suite.add(TestCase::new("boot::secure_boot_stats_fields", boot::test_secure_boot_stats_fields));
    suite.add(TestCase::new("boot::secure_boot_result_ok", boot::test_secure_boot_result_ok));
    suite.add(TestCase::new("boot::secure_boot_result_err", boot::test_secure_boot_result_err));
    suite.add(TestCase::new(
        "boot::secure_boot_error_equality",
        boot::test_secure_boot_error_equality,
    ));
    suite.add(TestCase::new(
        "boot::boot_measurements_with_initrd",
        boot::test_boot_measurements_with_initrd,
    ));
    suite.add(TestCase::new(
        "boot::boot_measurements_with_acpi",
        boot::test_boot_measurements_with_acpi,
    ));
    suite.add(TestCase::new("boot::boot_measurements_clone", boot::test_boot_measurements_clone));
    suite.add(TestCase::new("boot::trusted_key_creation", boot::test_trusted_key_creation));
    suite.add(TestCase::new("boot::trusted_key_expiration", boot::test_trusted_key_expiration));
    suite.add(TestCase::new("boot::trusted_key_timestamps", boot::test_trusted_key_timestamps));

    // Constant-time operation tests
    suite.add(TestCase::new(
        "constant_time::ct_compare_equal_slices",
        constant_time::test_ct_compare_equal_slices,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_compare_unequal_slices",
        constant_time::test_ct_compare_unequal_slices,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_compare_different_lengths",
        constant_time::test_ct_compare_different_lengths,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_compare_empty_slices",
        constant_time::test_ct_compare_empty_slices,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_compare_single_byte_equal",
        constant_time::test_ct_compare_single_byte_equal,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_compare_single_byte_unequal",
        constant_time::test_ct_compare_single_byte_unequal,
    ));
    suite.add(TestCase::new("constant_time::ct_verify_equal", constant_time::test_ct_verify_equal));
    suite.add(TestCase::new(
        "constant_time::ct_verify_not_equal",
        constant_time::test_ct_verify_not_equal,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_verify_result_equality",
        constant_time::test_ct_verify_result_equality,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_select_u8_condition_true",
        constant_time::test_ct_select_u8_condition_true,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_select_u8_condition_false",
        constant_time::test_ct_select_u8_condition_false,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_select_u32_condition_true",
        constant_time::test_ct_select_u32_condition_true,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_select_u32_condition_false",
        constant_time::test_ct_select_u32_condition_false,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_select_u64_condition_true",
        constant_time::test_ct_select_u64_condition_true,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_select_u64_condition_false",
        constant_time::test_ct_select_u64_condition_false,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_select_slice_condition_true",
        constant_time::test_ct_select_slice_condition_true,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_select_slice_condition_false",
        constant_time::test_ct_select_slice_condition_false,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_swap_slices_condition_true",
        constant_time::test_ct_swap_slices_condition_true,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_swap_slices_condition_false",
        constant_time::test_ct_swap_slices_condition_false,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_lt_u32_less_than",
        constant_time::test_ct_lt_u32_less_than,
    ));
    suite.add(TestCase::new("constant_time::ct_lt_u32_equal", constant_time::test_ct_lt_u32_equal));
    suite.add(TestCase::new(
        "constant_time::ct_lt_u32_greater_than",
        constant_time::test_ct_lt_u32_greater_than,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_lt_u64_less_than",
        constant_time::test_ct_lt_u64_less_than,
    ));
    suite.add(TestCase::new("constant_time::ct_lt_u64_equal", constant_time::test_ct_lt_u64_equal));
    suite.add(TestCase::new(
        "constant_time::ct_lt_u64_greater_than",
        constant_time::test_ct_lt_u64_greater_than,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_gt_u32_greater_than",
        constant_time::test_ct_gt_u32_greater_than,
    ));
    suite.add(TestCase::new("constant_time::ct_gt_u32_equal", constant_time::test_ct_gt_u32_equal));
    suite.add(TestCase::new(
        "constant_time::ct_gt_u32_less_than",
        constant_time::test_ct_gt_u32_less_than,
    ));
    suite.add(TestCase::new("constant_time::ct_eq_u32_equal", constant_time::test_ct_eq_u32_equal));
    suite.add(TestCase::new(
        "constant_time::ct_eq_u32_not_equal",
        constant_time::test_ct_eq_u32_not_equal,
    ));
    suite.add(TestCase::new("constant_time::ct_eq_u64_equal", constant_time::test_ct_eq_u64_equal));
    suite.add(TestCase::new(
        "constant_time::ct_eq_u64_not_equal",
        constant_time::test_ct_eq_u64_not_equal,
    ));
    suite.add(TestCase::new("constant_time::ct_min_u32", constant_time::test_ct_min_u32));
    suite.add(TestCase::new("constant_time::ct_max_u32", constant_time::test_ct_max_u32));
    suite.add(TestCase::new(
        "constant_time::ct_copy_bounded_full_copy",
        constant_time::test_ct_copy_bounded_full_copy,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_copy_bounded_partial_copy",
        constant_time::test_ct_copy_bounded_partial_copy,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_copy_bounded_zero_length",
        constant_time::test_ct_copy_bounded_zero_length,
    ));
    suite.add(TestCase::new("constant_time::ct_zero_slice", constant_time::test_ct_zero_slice));
    suite.add(TestCase::new(
        "constant_time::ct_zero_u64_slice",
        constant_time::test_ct_zero_u64_slice,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_hmac_verify_matching",
        constant_time::test_ct_hmac_verify_matching,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_hmac_verify_non_matching",
        constant_time::test_ct_hmac_verify_non_matching,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_signature_verify_matching",
        constant_time::test_ct_signature_verify_matching,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_signature_verify_non_matching",
        constant_time::test_ct_signature_verify_non_matching,
    ));
    suite.add(TestCase::new(
        "constant_time::timing_mode_variants",
        constant_time::test_timing_mode_variants,
    ));
    suite.add(TestCase::new(
        "constant_time::self_test_result_fields",
        constant_time::test_self_test_result_fields,
    ));
    suite.add(TestCase::new(
        "constant_time::self_test_result_with_failure",
        constant_time::test_self_test_result_with_failure,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_verify_result_invalid_input_variant",
        constant_time::test_ct_verify_result_invalid_input_variant,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_compare_all_zeros",
        constant_time::test_ct_compare_all_zeros,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_compare_all_ones",
        constant_time::test_ct_compare_all_ones,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_compare_first_byte_differs",
        constant_time::test_ct_compare_first_byte_differs,
    ));
    suite.add(TestCase::new(
        "constant_time::ct_compare_last_byte_differs",
        constant_time::test_ct_compare_last_byte_differs,
    ));

    // Secure random tests
    suite.add(TestCase::new(
        "random::secure_random_u64_returns_value",
        random::test_secure_random_u64_returns_value,
    ));
    suite.add(TestCase::new(
        "random::secure_random_u64_produces_different_values",
        random::test_secure_random_u64_produces_different_values,
    ));
    suite.add(TestCase::new(
        "random::secure_random_u32_returns_value",
        random::test_secure_random_u32_returns_value,
    ));
    suite.add(TestCase::new(
        "random::secure_random_u32_produces_different_values",
        random::test_secure_random_u32_produces_different_values,
    ));
    suite.add(TestCase::new(
        "random::secure_random_u8_returns_value",
        random::test_secure_random_u8_returns_value,
    ));
    suite.add(TestCase::new(
        "random::fill_random_small_buffer",
        random::test_fill_random_small_buffer,
    ));
    suite.add(TestCase::new(
        "random::fill_random_large_buffer",
        random::test_fill_random_large_buffer,
    ));
    suite.add(TestCase::new(
        "random::fill_random_different_calls",
        random::test_fill_random_different_calls,
    ));
    suite.add(TestCase::new(
        "random::fill_random_empty_buffer",
        random::test_fill_random_empty_buffer,
    ));
    suite.add(TestCase::new(
        "random::fill_random_single_byte",
        random::test_fill_random_single_byte,
    ));
    suite.add(TestCase::new(
        "random::fill_random_non_aligned_size",
        random::test_fill_random_non_aligned_size,
    ));
    suite.add(TestCase::new(
        "random::fill_random_exactly_u64_size",
        random::test_fill_random_exactly_u64_size,
    ));
    suite.add(TestCase::new(
        "random::fill_random_multiple_of_u64",
        random::test_fill_random_multiple_of_u64,
    ));
    suite.add(TestCase::new(
        "random::secure_random_u64_nonzero_probability",
        random::test_secure_random_u64_nonzero_probability,
    ));
    suite.add(TestCase::new(
        "random::secure_random_u32_range",
        random::test_secure_random_u32_range,
    ));
    suite.add(TestCase::new("random::secure_random_u8_range", random::test_secure_random_u8_range));
    suite.add(TestCase::new(
        "random::fill_random_all_bytes_potentially_nonzero",
        random::test_fill_random_all_bytes_potentially_nonzero,
    ));
    suite.add(TestCase::new(
        "random::secure_random_u64_statistical_distribution",
        random::test_secure_random_u64_statistical_distribution,
    ));
    suite.add(TestCase::new(
        "random::fill_random_byte_distribution",
        random::test_fill_random_byte_distribution,
    ));
    suite.add(TestCase::new(
        "random::secure_random_u64_bit_coverage",
        random::test_secure_random_u64_bit_coverage,
    ));
    suite.add(TestCase::new(
        "random::fill_random_independence",
        random::test_fill_random_independence,
    ));

    // Trusted keys tests
    suite.add(TestCase::new(
        "trusted_keys::trusted_key_struct_fields",
        trusted_keys::test_trusted_key_struct_fields,
    ));
    suite.add(TestCase::new(
        "trusted_keys::trusted_key_equality",
        trusted_keys::test_trusted_key_equality,
    ));
    suite.add(TestCase::new(
        "trusted_keys::trusted_key_inequality_name",
        trusted_keys::test_trusted_key_inequality_name,
    ));
    suite.add(TestCase::new(
        "trusted_keys::trusted_key_inequality_data",
        trusted_keys::test_trusted_key_inequality_data,
    ));
    suite.add(TestCase::new(
        "trusted_keys::trusted_key_clone",
        trusted_keys::test_trusted_key_clone,
    ));
    suite.add(TestCase::new(
        "trusted_keys::trusted_key_empty_key_data",
        trusted_keys::test_trusted_key_empty_key_data,
    ));
    suite.add(TestCase::new(
        "trusted_keys::trusted_key_32_byte_key",
        trusted_keys::test_trusted_key_32_byte_key,
    ));
    suite.add(TestCase::new(
        "trusted_keys::trusted_key_name_with_dots",
        trusted_keys::test_trusted_key_name_with_dots,
    ));
    suite.add(TestCase::new(
        "trusted_keys::trusted_hash_db_empty",
        trusted_keys::test_trusted_hash_db_empty,
    ));
    suite.add(TestCase::new("trusted_keys::add_trusted_hash", trusted_keys::test_add_trusted_hash));
    suite.add(TestCase::new(
        "trusted_keys::get_trusted_hash_not_found",
        trusted_keys::test_get_trusted_hash_not_found,
    ));
    suite.add(TestCase::new(
        "trusted_keys::verify_integrity_with_matching_hash",
        trusted_keys::test_verify_integrity_with_matching_hash,
    ));
    suite.add(TestCase::new(
        "trusted_keys::verify_integrity_with_mismatched_hash",
        trusted_keys::test_verify_integrity_with_mismatched_hash,
    ));
    suite.add(TestCase::new(
        "trusted_keys::verify_integrity_unknown_name",
        trusted_keys::test_verify_integrity_unknown_name,
    ));
    suite.add(TestCase::new(
        "trusted_keys::list_trusted_hashes_returns_vec",
        trusted_keys::test_list_trusted_hashes_returns_vec,
    ));
    suite.add(TestCase::new(
        "trusted_keys::trusted_key_db_add_and_get",
        trusted_keys::test_trusted_key_db_add_and_get,
    ));
    suite.add(TestCase::new(
        "trusted_keys::trusted_key_db_get_nonexistent",
        trusted_keys::test_trusted_key_db_get_nonexistent,
    ));
    suite.add(TestCase::new(
        "trusted_keys::list_trusted_keys_returns_vec",
        trusted_keys::test_list_trusted_keys_returns_vec,
    ));
    suite.add(TestCase::new(
        "trusted_keys::get_trusted_keys_returns_vec",
        trusted_keys::test_get_trusted_keys_returns_vec,
    ));
    suite.add(TestCase::new(
        "trusted_keys::add_trusted_key_overwrites",
        trusted_keys::test_add_trusted_key_overwrites,
    ));
    suite.add(TestCase::new(
        "trusted_keys::add_trusted_key_empty_data",
        trusted_keys::test_add_trusted_key_empty_data,
    ));
    suite.add(TestCase::new(
        "trusted_keys::add_trusted_key_large_data",
        trusted_keys::test_add_trusted_key_large_data,
    ));
    suite.add(TestCase::new(
        "trusted_keys::trusted_key_db_multiple_keys",
        trusted_keys::test_trusted_key_db_multiple_keys,
    ));
    suite.add(TestCase::new(
        "trusted_keys::trusted_hash_32_bytes",
        trusted_keys::test_trusted_hash_32_bytes,
    ));
    suite.add(TestCase::new(
        "trusted_keys::list_trusted_hashes_contains_added",
        trusted_keys::test_list_trusted_hashes_contains_added,
    ));
    suite.add(TestCase::new(
        "trusted_keys::trusted_key_debug_format",
        trusted_keys::test_trusted_key_debug_format,
    ));

    // CPU hardening tests
    suite.add(TestCase::new(
        "hardening::cpu_vulnerabilities_default",
        hardening::test_cpu_vulnerabilities_default,
    ));
    suite.add(TestCase::new(
        "hardening::cpu_vulnerabilities_all_fields",
        hardening::test_cpu_vulnerabilities_all_fields,
    ));
    suite.add(TestCase::new(
        "hardening::cpu_vulnerabilities_copy",
        hardening::test_cpu_vulnerabilities_copy,
    ));
    suite.add(TestCase::new(
        "hardening::cpu_vulnerabilities_clone",
        hardening::test_cpu_vulnerabilities_clone,
    ));
    suite.add(TestCase::new(
        "hardening::mitigation_status_default",
        hardening::test_mitigation_status_default,
    ));
    suite.add(TestCase::new(
        "hardening::mitigation_status_all_enabled",
        hardening::test_mitigation_status_all_enabled,
    ));
    suite.add(TestCase::new(
        "hardening::mitigation_status_copy",
        hardening::test_mitigation_status_copy,
    ));
    suite.add(TestCase::new(
        "hardening::mitigation_status_clone",
        hardening::test_mitigation_status_clone,
    ));
    suite.add(TestCase::new(
        "hardening::mitigation_status_partial_enabled",
        hardening::test_mitigation_status_partial_enabled,
    ));
    suite.add(TestCase::new("hardening::lfence_barrier", hardening::test_lfence_barrier));
    suite.add(TestCase::new("hardening::mfence_barrier", hardening::test_mfence_barrier));
    suite.add(TestCase::new("hardening::sfence_barrier", hardening::test_sfence_barrier));
    suite.add(TestCase::new(
        "hardening::array_index_mask_nospec",
        hardening::test_array_index_mask_nospec,
    ));
    suite.add(TestCase::new(
        "hardening::array_index_mask_nospec_out_of_bounds",
        hardening::test_array_index_mask_nospec_out_of_bounds,
    ));
    suite.add(TestCase::new(
        "hardening::array_index_mask_nospec_boundary",
        hardening::test_array_index_mask_nospec_boundary,
    ));
    suite.add(TestCase::new("hardening::array_access_nospec", hardening::test_array_access_nospec));
    suite.add(TestCase::new(
        "hardening::array_access_nospec_first_element",
        hardening::test_array_access_nospec_first_element,
    ));
    suite.add(TestCase::new(
        "hardening::array_access_nospec_last_element",
        hardening::test_array_access_nospec_last_element,
    ));
    suite.add(TestCase::new("hardening::rsb_fill", hardening::test_rsb_fill));
    suite.add(TestCase::new("hardening::rsb_clear", hardening::test_rsb_clear));
    suite.add(TestCase::new("hardening::l1d_flush", hardening::test_l1d_flush));
    suite.add(TestCase::new("hardening::mds_clear", hardening::test_mds_clear));
    suite.add(TestCase::new(
        "hardening::kernel_entry_mitigations",
        hardening::test_kernel_entry_mitigations,
    ));
    suite.add(TestCase::new(
        "hardening::kernel_exit_mitigations",
        hardening::test_kernel_exit_mitigations,
    ));
    suite.add(TestCase::new(
        "hardening::context_switch_mitigations",
        hardening::test_context_switch_mitigations,
    ));
    suite.add(TestCase::new("hardening::get_vulnerabilities", hardening::test_get_vulnerabilities));
    suite.add(TestCase::new(
        "hardening::get_mitigation_status",
        hardening::test_get_mitigation_status,
    ));
    suite.add(TestCase::new(
        "hardening::are_mitigations_enabled",
        hardening::test_are_mitigations_enabled,
    ));
    suite.add(TestCase::new(
        "hardening::cpu_vulnerabilities_debug_format",
        hardening::test_cpu_vulnerabilities_debug_format,
    ));
    suite.add(TestCase::new(
        "hardening::mitigation_status_debug_format",
        hardening::test_mitigation_status_debug_format,
    ));
    suite.add(TestCase::new(
        "hardening::vulnerability_fields_are_bools",
        hardening::test_vulnerability_fields_are_bools,
    ));
    suite.add(TestCase::new(
        "hardening::mitigation_fields_are_bools",
        hardening::test_mitigation_fields_are_bools,
    ));

    // Memory sanitization tests
    suite.add(TestCase::new(
        "sanitization::sanitization_level_none",
        sanitization::test_sanitization_level_none,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_level_basic",
        sanitization::test_sanitization_level_basic,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_level_standard",
        sanitization::test_sanitization_level_standard,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_level_paranoid",
        sanitization::test_sanitization_level_paranoid,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_level_gutmann",
        sanitization::test_sanitization_level_gutmann,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_level_default",
        sanitization::test_sanitization_level_default,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_level_from_u64_none",
        sanitization::test_sanitization_level_from_u64_none,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_level_from_u64_basic",
        sanitization::test_sanitization_level_from_u64_basic,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_level_from_u64_standard",
        sanitization::test_sanitization_level_from_u64_standard,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_level_from_u64_paranoid",
        sanitization::test_sanitization_level_from_u64_paranoid,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_level_from_u64_gutmann",
        sanitization::test_sanitization_level_from_u64_gutmann,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_level_from_u64_invalid",
        sanitization::test_sanitization_level_from_u64_invalid,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_level_equality",
        sanitization::test_sanitization_level_equality,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_level_copy",
        sanitization::test_sanitization_level_copy,
    ));
    suite.add(TestCase::new(
        "sanitization::stack_canary_config_default",
        sanitization::test_stack_canary_config_default,
    ));
    suite.add(TestCase::new(
        "sanitization::stack_canary_config_is_enabled",
        sanitization::test_stack_canary_config_is_enabled,
    ));
    suite.add(TestCase::new(
        "sanitization::stack_canary_config_get_canary",
        sanitization::test_stack_canary_config_get_canary,
    ));
    suite.add(TestCase::new(
        "sanitization::stack_canary_config_get_frequency",
        sanitization::test_stack_canary_config_get_frequency,
    ));
    suite.add(TestCase::new(
        "sanitization::stack_canary_config_verify_correct",
        sanitization::test_stack_canary_config_verify_correct,
    ));
    suite.add(TestCase::new(
        "sanitization::stack_canary_config_verify_incorrect",
        sanitization::test_stack_canary_config_verify_incorrect,
    ));
    suite.add(TestCase::new(
        "sanitization::stack_canary_config_verify_disabled",
        sanitization::test_stack_canary_config_verify_disabled,
    ));
    suite.add(TestCase::new(
        "sanitization::stack_canary_config_custom",
        sanitization::test_stack_canary_config_custom,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_stats_fields",
        sanitization::test_sanitization_stats_fields,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_stats_get_bytes_sanitized",
        sanitization::test_sanitization_stats_get_bytes_sanitized,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_stats_get_call_count",
        sanitization::test_sanitization_stats_get_call_count,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_stats_get_level",
        sanitization::test_sanitization_stats_get_level,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_stats_is_canary_enabled",
        sanitization::test_sanitization_stats_is_canary_enabled,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_stats_avg_bytes_per_call",
        sanitization::test_sanitization_stats_avg_bytes_per_call,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_stats_avg_bytes_per_call_zero_calls",
        sanitization::test_sanitization_stats_avg_bytes_per_call_zero_calls,
    ));
    suite.add(TestCase::new(
        "sanitization::secure_zero_small_buffer",
        sanitization::test_secure_zero_small_buffer,
    ));
    suite.add(TestCase::new(
        "sanitization::secure_zero_large_buffer",
        sanitization::test_secure_zero_large_buffer,
    ));
    suite.add(TestCase::new(
        "sanitization::secure_zero_slice",
        sanitization::test_secure_zero_slice,
    ));
    suite.add(TestCase::new(
        "sanitization::secure_zero_empty",
        sanitization::test_secure_zero_empty,
    ));
    suite.add(TestCase::new(
        "sanitization::secure_zero_single_byte",
        sanitization::test_secure_zero_single_byte,
    ));
    suite.add(TestCase::new("sanitization::sanitize_slice", sanitization::test_sanitize_slice));
    suite.add(TestCase::new(
        "sanitization::init_stack_canary",
        sanitization::test_init_stack_canary,
    ));
    suite.add(TestCase::new("sanitization::get_stack_canary", sanitization::test_get_stack_canary));
    suite.add(TestCase::new(
        "sanitization::verify_stack_canary_correct",
        sanitization::test_verify_stack_canary_correct,
    ));
    suite.add(TestCase::new(
        "sanitization::verify_stack_canary_incorrect",
        sanitization::test_verify_stack_canary_incorrect,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_level_debug",
        sanitization::test_sanitization_level_debug,
    ));
    suite.add(TestCase::new(
        "sanitization::stack_canary_config_debug",
        sanitization::test_stack_canary_config_debug,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_stats_debug",
        sanitization::test_sanitization_stats_debug,
    ));
    suite.add(TestCase::new(
        "sanitization::sanitization_stats_copy",
        sanitization::test_sanitization_stats_copy,
    ));
    suite.add(TestCase::new(
        "sanitization::stack_canary_config_copy",
        sanitization::test_stack_canary_config_copy,
    ));

    // Security audit tests
    suite.add(TestCase::new("audit::audit_severity_info", audit::test_audit_severity_info));
    suite.add(TestCase::new("audit::audit_severity_warning", audit::test_audit_severity_warning));
    suite.add(TestCase::new("audit::audit_severity_error", audit::test_audit_severity_error));
    suite.add(TestCase::new("audit::audit_severity_critical", audit::test_audit_severity_critical));
    suite.add(TestCase::new(
        "audit::audit_severity_emergency",
        audit::test_audit_severity_emergency,
    ));
    suite.add(TestCase::new("audit::audit_severity_equality", audit::test_audit_severity_equality));
    suite.add(TestCase::new("audit::audit_severity_copy", audit::test_audit_severity_copy));
    suite.add(TestCase::new(
        "audit::security_audit_event_fields",
        audit::test_security_audit_event_fields,
    ));
    suite.add(TestCase::new(
        "audit::security_audit_event_minimal",
        audit::test_security_audit_event_minimal,
    ));
    suite.add(TestCase::new(
        "audit::security_audit_event_clone",
        audit::test_security_audit_event_clone,
    ));
    suite.add(TestCase::new("audit::log_security_event", audit::test_log_security_event));
    suite.add(TestCase::new(
        "audit::log_security_event_minimal",
        audit::test_log_security_event_minimal,
    ));
    suite.add(TestCase::new("audit::log_security_violation", audit::test_log_security_violation));
    suite.add(TestCase::new("audit::get_audit_log", audit::test_get_audit_log));
    suite.add(TestCase::new("audit::clear_audit_log", audit::test_clear_audit_log));
    suite.add(TestCase::new("audit::audit_event_alias", audit::test_audit_event_alias));
    suite.add(TestCase::new("audit::audit_event_function", audit::test_audit_event_function));
    suite.add(TestCase::new(
        "audit::audit_log_multiple_events",
        audit::test_audit_log_multiple_events,
    ));
    suite.add(TestCase::new(
        "audit::audit_severity_all_variants",
        audit::test_audit_severity_all_variants,
    ));
    suite.add(TestCase::new(
        "audit::security_audit_event_with_tags",
        audit::test_security_audit_event_with_tags,
    ));
    suite.add(TestCase::new(
        "audit::audit_event_debug_format",
        audit::test_audit_event_debug_format,
    ));
    suite.add(TestCase::new(
        "audit::audit_severity_debug_format",
        audit::test_audit_severity_debug_format,
    ));
    suite.add(TestCase::new(
        "audit::log_security_event_all_fields",
        audit::test_log_security_event_all_fields,
    ));
    suite.add(TestCase::new(
        "audit::security_audit_event_timestamp_range",
        audit::test_security_audit_event_timestamp_range,
    ));
    suite.add(TestCase::new(
        "audit::security_audit_event_empty_description",
        audit::test_security_audit_event_empty_description,
    ));

    // Session management tests
    suite.add(TestCase::new("session::uid_root_constant", session::test_uid_root_constant));
    suite.add(TestCase::new(
        "session::uid_anonymous_constant",
        session::test_uid_anonymous_constant,
    ));
    suite.add(TestCase::new("session::uid_default_constant", session::test_uid_default_constant));
    suite.add(TestCase::new("session::gid_root_constant", session::test_gid_root_constant));
    suite.add(TestCase::new("session::gid_wheel_constant", session::test_gid_wheel_constant));
    suite.add(TestCase::new("session::gid_users_constant", session::test_gid_users_constant));
    suite.add(TestCase::new("session::privilege_level_root", session::test_privilege_level_root));
    suite.add(TestCase::new("session::privilege_level_admin", session::test_privilege_level_admin));
    suite.add(TestCase::new("session::privilege_level_user", session::test_privilege_level_user));
    suite.add(TestCase::new("session::privilege_level_guest", session::test_privilege_level_guest));
    suite.add(TestCase::new(
        "session::privilege_level_anonymous",
        session::test_privilege_level_anonymous,
    ));
    suite.add(TestCase::new(
        "session::privilege_level_equality",
        session::test_privilege_level_equality,
    ));
    suite.add(TestCase::new("session::privilege_level_copy", session::test_privilege_level_copy));
    suite.add(TestCase::new("session::session_state_active", session::test_session_state_active));
    suite.add(TestCase::new("session::session_state_idle", session::test_session_state_idle));
    suite.add(TestCase::new("session::session_state_locked", session::test_session_state_locked));
    suite.add(TestCase::new("session::session_state_expired", session::test_session_state_expired));
    suite.add(TestCase::new(
        "session::session_state_terminated",
        session::test_session_state_terminated,
    ));
    suite.add(TestCase::new(
        "session::session_state_equality",
        session::test_session_state_equality,
    ));
    suite.add(TestCase::new("session::session_state_copy", session::test_session_state_copy));
    suite.add(TestCase::new("session::all_privilege_levels", session::test_all_privilege_levels));
    suite.add(TestCase::new("session::all_session_states", session::test_all_session_states));
    suite.add(TestCase::new(
        "session::privilege_level_debug_format",
        session::test_privilege_level_debug_format,
    ));
    suite.add(TestCase::new(
        "session::session_state_debug_format",
        session::test_session_state_debug_format,
    ));
    suite.add(TestCase::new("session::current_uid", session::test_current_uid));
    suite.add(TestCase::new("session::current_username", session::test_current_username));
    suite.add(TestCase::new("session::current_cwd", session::test_current_cwd));
    suite.add(TestCase::new("session::getenv_path", session::test_getenv_path));
    suite.add(TestCase::new("session::getenv_nonexistent", session::test_getenv_nonexistent));
    suite.add(TestCase::new("session::setenv_custom", session::test_setenv_custom));
    suite.add(TestCase::new("session::environ", session::test_environ));
    suite.add(TestCase::new("session::session_stats_fields", session::test_session_stats_fields));
    suite.add(TestCase::new(
        "session::uid_constants_distinct",
        session::test_uid_constants_distinct,
    ));
    suite.add(TestCase::new(
        "session::gid_constants_distinct",
        session::test_gid_constants_distinct,
    ));
    suite.add(TestCase::new("session::privilege_hierarchy", session::test_privilege_hierarchy));
    suite.add(TestCase::new(
        "session::session_state_transitions",
        session::test_session_state_transitions,
    ));
    suite.add(TestCase::new("session::setenv_overwrite", session::test_setenv_overwrite));
    suite.add(TestCase::new("session::setenv_empty_value", session::test_setenv_empty_value));
    suite.add(TestCase::new("session::chdir", session::test_chdir));
    suite.add(TestCase::new("session::chdir_root", session::test_chdir_root));
    suite.add(TestCase::new(
        "session::session_manager_exists",
        session::test_session_manager_exists,
    ));

    // Observability tests
    suite.add(TestCase::new(
        "observability::output_mode_minimal",
        observability::test_output_mode_minimal,
    ));
    suite.add(TestCase::new(
        "observability::output_mode_standard",
        observability::test_output_mode_standard,
    ));
    suite.add(TestCase::new(
        "observability::output_mode_verbose",
        observability::test_output_mode_verbose,
    ));
    suite.add(TestCase::new(
        "observability::output_mode_debug",
        observability::test_output_mode_debug,
    ));
    suite.add(TestCase::new(
        "observability::output_mode_from_u8_minimal",
        observability::test_output_mode_from_u8_minimal,
    ));
    suite.add(TestCase::new(
        "observability::output_mode_from_u8_standard",
        observability::test_output_mode_from_u8_standard,
    ));
    suite.add(TestCase::new(
        "observability::output_mode_from_u8_verbose",
        observability::test_output_mode_from_u8_verbose,
    ));
    suite.add(TestCase::new(
        "observability::output_mode_from_u8_debug",
        observability::test_output_mode_from_u8_debug,
    ));
    suite.add(TestCase::new(
        "observability::output_mode_from_u8_invalid",
        observability::test_output_mode_from_u8_invalid,
    ));
    suite.add(TestCase::new(
        "observability::output_mode_equality",
        observability::test_output_mode_equality,
    ));
    suite.add(TestCase::new(
        "observability::output_mode_copy",
        observability::test_output_mode_copy,
    ));
    suite.add(TestCase::new(
        "observability::observability_policy_default",
        observability::test_observability_policy_default,
    ));
    suite.add(TestCase::new(
        "observability::observability_policy_custom",
        observability::test_observability_policy_custom,
    ));
    suite.add(TestCase::new(
        "observability::observability_policy_copy",
        observability::test_observability_policy_copy,
    ));
    suite.add(TestCase::new(
        "observability::is_production_mode",
        observability::test_is_production_mode,
    ));
    suite.add(TestCase::new(
        "observability::set_production_mode_true",
        observability::test_set_production_mode_true,
    ));
    suite.add(TestCase::new(
        "observability::set_production_mode_false",
        observability::test_set_production_mode_false,
    ));
    suite.add(TestCase::new(
        "observability::should_log_debug_production",
        observability::test_should_log_debug_production,
    ));
    suite.add(TestCase::new(
        "observability::should_emit_serial",
        observability::test_should_emit_serial,
    ));
    suite.add(TestCase::new(
        "observability::redact_pointer_production",
        observability::test_redact_pointer_production,
    ));
    suite.add(TestCase::new(
        "observability::redact_pointer_development",
        observability::test_redact_pointer_development,
    ));
    suite.add(TestCase::new(
        "observability::redact_address_production",
        observability::test_redact_address_production,
    ));
    suite.add(TestCase::new(
        "observability::redact_address_development",
        observability::test_redact_address_development,
    ));
    suite.add(TestCase::new(
        "observability::redact_panic_message_production",
        observability::test_redact_panic_message_production,
    ));
    suite.add(TestCase::new(
        "observability::redact_panic_message_development",
        observability::test_redact_panic_message_development,
    ));
    suite.add(TestCase::new(
        "observability::redact_panic_message_with_address",
        observability::test_redact_panic_message_with_address,
    ));
    suite.add(TestCase::new(
        "observability::observability_policy_debug_format",
        observability::test_observability_policy_debug_format,
    ));
    suite.add(TestCase::new(
        "observability::output_mode_debug_format",
        observability::test_output_mode_debug_format,
    ));
    suite.add(TestCase::new(
        "observability::all_output_modes",
        observability::test_all_output_modes,
    ));
    suite.add(TestCase::new(
        "observability::output_mode_ordering",
        observability::test_output_mode_ordering,
    ));
    suite.add(TestCase::new(
        "observability::redact_pointer_zero",
        observability::test_redact_pointer_zero,
    ));
    suite.add(TestCase::new(
        "observability::redact_address_zero",
        observability::test_redact_address_zero,
    ));
    suite.add(TestCase::new(
        "observability::redact_pointer_max",
        observability::test_redact_pointer_max,
    ));
    suite.add(TestCase::new(
        "observability::redact_address_max",
        observability::test_redact_address_max,
    ));
    suite.add(TestCase::new(
        "observability::redact_panic_message_empty",
        observability::test_redact_panic_message_empty,
    ));
    suite.add(TestCase::new(
        "observability::redact_panic_message_no_sensitive_data",
        observability::test_redact_panic_message_no_sensitive_data,
    ));
    suite.add(TestCase::new(
        "observability::production_mode_toggle",
        observability::test_production_mode_toggle,
    ));
    suite.add(TestCase::new(
        "observability::observability_policy_all_disabled",
        observability::test_observability_policy_all_disabled,
    ));
    suite.add(TestCase::new(
        "observability::observability_policy_all_enabled",
        observability::test_observability_policy_all_enabled,
    ));
    suite.add(TestCase::new("observability::serial_log", observability::test_serial_log));
    suite.add(TestCase::new(
        "observability::serial_log_redacted",
        observability::test_serial_log_redacted,
    ));

    // ZKIDS tests
    suite.add(TestCase::new("zkids::zkid_fields", zkids::test_zkid_fields));
    suite.add(TestCase::new("zkids::zkid_clone", zkids::test_zkid_clone));
    suite.add(TestCase::new("zkids::zkid_with_capabilities", zkids::test_zkid_with_capabilities));
    suite.add(TestCase::new("zkids::capability_system_admin", zkids::test_capability_system_admin));
    suite.add(TestCase::new(
        "zkids::capability_process_manager",
        zkids::test_capability_process_manager,
    ));
    suite.add(TestCase::new(
        "zkids::capability_memory_manager",
        zkids::test_capability_memory_manager,
    ));
    suite.add(TestCase::new(
        "zkids::capability_network_admin",
        zkids::test_capability_network_admin,
    ));
    suite.add(TestCase::new("zkids::capability_file_system", zkids::test_capability_file_system));
    suite.add(TestCase::new(
        "zkids::capability_crypto_operator",
        zkids::test_capability_crypto_operator,
    ));
    suite.add(TestCase::new(
        "zkids::capability_module_loader",
        zkids::test_capability_module_loader,
    ));
    suite.add(TestCase::new("zkids::capability_debug_access", zkids::test_capability_debug_access));
    suite.add(TestCase::new(
        "zkids::capability_time_critical",
        zkids::test_capability_time_critical,
    ));
    suite.add(TestCase::new("zkids::capability_custom", zkids::test_capability_custom));
    suite.add(TestCase::new("zkids::capability_equality", zkids::test_capability_equality));
    suite.add(TestCase::new("zkids::capability_clone", zkids::test_capability_clone));
    suite.add(TestCase::new("zkids::auth_challenge_fields", zkids::test_auth_challenge_fields));
    suite.add(TestCase::new("zkids::auth_challenge_clone", zkids::test_auth_challenge_clone));
    suite.add(TestCase::new("zkids::auth_session_fields", zkids::test_auth_session_fields));
    suite.add(TestCase::new("zkids::auth_session_clone", zkids::test_auth_session_clone));
    suite.add(TestCase::new("zkids::zkids_config_default", zkids::test_zkids_config_default));
    suite.add(TestCase::new("zkids::zkids_config_custom", zkids::test_zkids_config_custom));
    suite.add(TestCase::new("zkids::zkids_config_copy", zkids::test_zkids_config_copy));
    suite.add(TestCase::new("zkids::zkids_stats_fields", zkids::test_zkids_stats_fields));
    suite.add(TestCase::new("zkids::zkids_stats_clone", zkids::test_zkids_stats_clone));
    suite.add(TestCase::new("zkids::get_zkids_stats", zkids::test_get_zkids_stats));
    suite.add(TestCase::new("zkids::all_zkids_capabilities", zkids::test_all_zkids_capabilities));
    suite.add(TestCase::new("zkids::zkid_debug_format", zkids::test_zkid_debug_format));
    suite.add(TestCase::new("zkids::capability_debug_format", zkids::test_capability_debug_format));
    suite.add(TestCase::new(
        "zkids::zkids_stats_debug_format",
        zkids::test_zkids_stats_debug_format,
    ));
    suite.add(TestCase::new(
        "zkids::custom_capability_equality",
        zkids::test_custom_capability_equality,
    ));
    suite.add(TestCase::new(
        "zkids::zkid_with_max_auth_count",
        zkids::test_zkid_with_max_auth_count,
    ));
    suite.add(TestCase::new(
        "zkids::auth_challenge_empty_capabilities",
        zkids::test_auth_challenge_empty_capabilities,
    ));
    suite.add(TestCase::new("zkids::auth_session_expired", zkids::test_auth_session_expired));

    // Security crypto tests
    suite.add(TestCase::new(
        "crypto::key_type_ed25519_signing",
        crypto::test_key_type_ed25519_signing,
    ));
    suite.add(TestCase::new(
        "crypto::key_type_ed25519_verify",
        crypto::test_key_type_ed25519_verify,
    ));
    suite.add(TestCase::new(
        "crypto::key_type_x25519_exchange",
        crypto::test_key_type_x25519_exchange,
    ));
    suite.add(TestCase::new("crypto::key_type_aes256", crypto::test_key_type_aes256));
    suite.add(TestCase::new("crypto::key_type_chacha20", crypto::test_key_type_chacha20));
    suite.add(TestCase::new("crypto::key_type_hmac", crypto::test_key_type_hmac));
    suite.add(TestCase::new("crypto::key_type_master_key", crypto::test_key_type_master_key));
    suite.add(TestCase::new("crypto::key_type_mlkem_encap", crypto::test_key_type_mlkem_encap));
    suite.add(TestCase::new("crypto::key_type_mlkem_decap", crypto::test_key_type_mlkem_decap));
    suite.add(TestCase::new("crypto::key_type_mldsa_sign", crypto::test_key_type_mldsa_sign));
    suite.add(TestCase::new("crypto::key_type_mldsa_verify", crypto::test_key_type_mldsa_verify));
    suite.add(TestCase::new("crypto::key_type_equality", crypto::test_key_type_equality));
    suite.add(TestCase::new("crypto::key_type_clone", crypto::test_key_type_clone));
    suite.add(TestCase::new("crypto::key_type_copy", crypto::test_key_type_copy));
    suite.add(TestCase::new(
        "crypto::key_length_ed25519_signing",
        crypto::test_key_length_ed25519_signing,
    ));
    suite.add(TestCase::new(
        "crypto::key_length_ed25519_verify",
        crypto::test_key_length_ed25519_verify,
    ));
    suite.add(TestCase::new("crypto::key_length_x25519", crypto::test_key_length_x25519));
    suite.add(TestCase::new("crypto::key_length_aes256", crypto::test_key_length_aes256));
    suite.add(TestCase::new("crypto::key_length_chacha20", crypto::test_key_length_chacha20));
    suite.add(TestCase::new("crypto::key_length_hmac", crypto::test_key_length_hmac));
    suite.add(TestCase::new("crypto::key_length_master_key", crypto::test_key_length_master_key));
    suite.add(TestCase::new("crypto::key_length_mlkem_encap", crypto::test_key_length_mlkem_encap));
    suite.add(TestCase::new("crypto::key_length_mlkem_decap", crypto::test_key_length_mlkem_decap));
    suite.add(TestCase::new("crypto::key_length_mldsa_sign", crypto::test_key_length_mldsa_sign));
    suite.add(TestCase::new(
        "crypto::key_length_mldsa_verify",
        crypto::test_key_length_mldsa_verify,
    ));
    suite.add(TestCase::new("crypto::key_usage_signing", crypto::test_key_usage_signing));
    suite.add(TestCase::new("crypto::key_usage_verification", crypto::test_key_usage_verification));
    suite.add(TestCase::new("crypto::key_usage_encryption", crypto::test_key_usage_encryption));
    suite.add(TestCase::new("crypto::key_usage_key_exchange", crypto::test_key_usage_key_exchange));
    suite.add(TestCase::new("crypto::key_usage_master", crypto::test_key_usage_master));
    suite.add(TestCase::new("crypto::key_usage_clone", crypto::test_key_usage_clone));
    suite.add(TestCase::new("crypto::key_usage_copy", crypto::test_key_usage_copy));
    suite.add(TestCase::new("crypto::key_usage_equality", crypto::test_key_usage_equality));
    suite.add(TestCase::new("crypto::key_usage_custom", crypto::test_key_usage_custom));
    suite.add(TestCase::new("crypto::key_usage_all_false", crypto::test_key_usage_all_false));
    suite.add(TestCase::new("crypto::key_type_debug", crypto::test_key_type_debug));
    suite.add(TestCase::new("crypto::key_usage_debug", crypto::test_key_usage_debug));
    suite.add(TestCase::new("crypto::key_type_all_variants", crypto::test_key_type_all_variants));
    suite.add(TestCase::new("crypto::key_type_all_unique", crypto::test_key_type_all_unique));
    suite.add(TestCase::new("crypto::pqc_key_lengths_larger", crypto::test_pqc_key_lengths_larger));
    suite.add(TestCase::new(
        "crypto::symmetric_key_lengths_equal",
        crypto::test_symmetric_key_lengths_equal,
    ));
    suite.add(TestCase::new(
        "crypto::key_usage_preset_functions_const",
        crypto::test_key_usage_preset_functions_const,
    ));

    // Security monitoring tests
    suite.add(TestCase::new(
        "monitoring::security_event_type_suspicious_memory",
        monitoring::test_security_event_type_suspicious_memory,
    ));
    suite.add(TestCase::new(
        "monitoring::security_event_type_unauthorized_network",
        monitoring::test_security_event_type_unauthorized_network,
    ));
    suite.add(TestCase::new(
        "monitoring::security_event_type_process_anomaly",
        monitoring::test_security_event_type_process_anomaly,
    ));
    suite.add(TestCase::new(
        "monitoring::security_event_type_hardware_tamper",
        monitoring::test_security_event_type_hardware_tamper,
    ));
    suite.add(TestCase::new(
        "monitoring::security_event_type_privilege_escalation",
        monitoring::test_security_event_type_privilege_escalation,
    ));
    suite.add(TestCase::new(
        "monitoring::security_event_type_syscall_anomaly",
        monitoring::test_security_event_type_syscall_anomaly,
    ));
    suite.add(TestCase::new(
        "monitoring::security_event_type_filesystem_violation",
        monitoring::test_security_event_type_filesystem_violation,
    ));
    suite.add(TestCase::new(
        "monitoring::security_event_type_capability_abuse",
        monitoring::test_security_event_type_capability_abuse,
    ));
    suite.add(TestCase::new(
        "monitoring::security_event_type_privacy_violation",
        monitoring::test_security_event_type_privacy_violation,
    ));
    suite.add(TestCase::new(
        "monitoring::security_event_type_rootkit_detection",
        monitoring::test_security_event_type_rootkit_detection,
    ));
    suite.add(TestCase::new(
        "monitoring::security_event_type_integrity_breach",
        monitoring::test_security_event_type_integrity_breach,
    ));
    suite.add(TestCase::new(
        "monitoring::security_event_type_equality",
        monitoring::test_security_event_type_equality,
    ));
    suite.add(TestCase::new(
        "monitoring::security_event_type_clone",
        monitoring::test_security_event_type_clone,
    ));
    suite.add(TestCase::new(
        "monitoring::security_event_type_copy",
        monitoring::test_security_event_type_copy,
    ));
    suite.add(TestCase::new(
        "monitoring::security_event_fields",
        monitoring::test_security_event_fields,
    ));
    suite.add(TestCase::new(
        "monitoring::security_event_minimal",
        monitoring::test_security_event_minimal,
    ));
    suite.add(TestCase::new(
        "monitoring::security_event_clone",
        monitoring::test_security_event_clone,
    ));
    suite.add(TestCase::new("monitoring::log_event", monitoring::test_log_event));
    suite.add(TestCase::new("monitoring::log_event_minimal", monitoring::test_log_event_minimal));
    suite.add(TestCase::new(
        "monitoring::log_event_high_severity",
        monitoring::test_log_event_high_severity,
    ));
    suite.add(TestCase::new("monitoring::get_recent_events", monitoring::test_get_recent_events));
    suite.add(TestCase::new(
        "monitoring::get_recent_events_zero",
        monitoring::test_get_recent_events_zero,
    ));
    suite.add(TestCase::new("monitoring::get_stats", monitoring::test_get_stats));
    suite.add(TestCase::new("monitoring::set_enabled_true", monitoring::test_set_enabled_true));
    suite.add(TestCase::new("monitoring::set_enabled_false", monitoring::test_set_enabled_false));
    suite.add(TestCase::new("monitoring::is_enabled", monitoring::test_is_enabled));
    suite.add(TestCase::new(
        "monitoring::security_event_type_all_variants",
        monitoring::test_security_event_type_all_variants,
    ));
    suite.add(TestCase::new(
        "monitoring::security_event_type_all_unique",
        monitoring::test_security_event_type_all_unique,
    ));
    suite.add(TestCase::new(
        "monitoring::security_event_type_debug",
        monitoring::test_security_event_type_debug,
    ));
    suite.add(TestCase::new(
        "monitoring::security_event_debug",
        monitoring::test_security_event_debug,
    ));
    suite.add(TestCase::new(
        "monitoring::security_event_severity_range",
        monitoring::test_security_event_severity_range,
    ));
    suite.add(TestCase::new(
        "monitoring::log_multiple_events",
        monitoring::test_log_multiple_events,
    ));
    suite.add(TestCase::new(
        "monitoring::security_event_with_all_tags",
        monitoring::test_security_event_with_all_tags,
    ));
    suite.add(TestCase::new("monitoring::enabled_toggle", monitoring::test_enabled_toggle));

    // Security policy tests
    suite.add(TestCase::new(
        "policy::secure_boot_policy_disabled",
        policy::test_secure_boot_policy_disabled,
    ));
    suite.add(TestCase::new(
        "policy::secure_boot_policy_permissive",
        policy::test_secure_boot_policy_permissive,
    ));
    suite.add(TestCase::new(
        "policy::secure_boot_policy_enforcing",
        policy::test_secure_boot_policy_enforcing,
    ));
    suite.add(TestCase::new(
        "policy::secure_boot_policy_strict",
        policy::test_secure_boot_policy_strict,
    ));
    suite.add(TestCase::new(
        "policy::secure_boot_policy_equality",
        policy::test_secure_boot_policy_equality,
    ));
    suite.add(TestCase::new(
        "policy::secure_boot_policy_clone",
        policy::test_secure_boot_policy_clone,
    ));
    suite.add(TestCase::new(
        "policy::secure_boot_policy_copy",
        policy::test_secure_boot_policy_copy,
    ));
    suite.add(TestCase::new("policy::set_policy_disabled", policy::test_set_policy_disabled));
    suite.add(TestCase::new("policy::set_policy_permissive", policy::test_set_policy_permissive));
    suite.add(TestCase::new("policy::set_policy_enforcing", policy::test_set_policy_enforcing));
    suite.add(TestCase::new("policy::set_policy_strict", policy::test_set_policy_strict));
    suite.add(TestCase::new("policy::get_policy", policy::test_get_policy));
    suite.add(TestCase::new("policy::is_enforcing", policy::test_is_enforcing));
    suite.add(TestCase::new(
        "policy::policy_transition_disabled_to_enforcing",
        policy::test_policy_transition_disabled_to_enforcing,
    ));
    suite.add(TestCase::new(
        "policy::policy_transition_enforcing_to_disabled",
        policy::test_policy_transition_enforcing_to_disabled,
    ));
    suite.add(TestCase::new(
        "policy::policy_transition_permissive_to_strict",
        policy::test_policy_transition_permissive_to_strict,
    ));
    suite.add(TestCase::new(
        "policy::secure_boot_policy_all_variants",
        policy::test_secure_boot_policy_all_variants,
    ));
    suite.add(TestCase::new(
        "policy::secure_boot_policy_all_unique",
        policy::test_secure_boot_policy_all_unique,
    ));
    suite.add(TestCase::new(
        "policy::secure_boot_policy_debug",
        policy::test_secure_boot_policy_debug,
    ));
    suite.add(TestCase::new("policy::enforcing_policies", policy::test_enforcing_policies));
    suite.add(TestCase::new("policy::non_enforcing_policies", policy::test_non_enforcing_policies));
    suite.add(TestCase::new("policy::policy_roundtrip", policy::test_policy_roundtrip));
    suite.add(TestCase::new(
        "policy::multiple_set_policy_calls",
        policy::test_multiple_set_policy_calls,
    ));
    suite.add(TestCase::new("policy::policy_idempotent", policy::test_policy_idempotent));

    // Quantum security tests
    suite.add(TestCase::new(
        "quantum::quantum_particle_fields",
        quantum::test_quantum_particle_fields,
    ));
    suite.add(TestCase::new(
        "quantum::quantum_particle_state_vector_size",
        quantum::test_quantum_particle_state_vector_size,
    ));
    suite.add(TestCase::new(
        "quantum::quantum_particle_normalized_state",
        quantum::test_quantum_particle_normalized_state,
    ));
    suite.add(TestCase::new(
        "quantum::quantum_particle_spin_up",
        quantum::test_quantum_particle_spin_up,
    ));
    suite.add(TestCase::new(
        "quantum::quantum_particle_spin_down",
        quantum::test_quantum_particle_spin_down,
    ));
    suite.add(TestCase::new(
        "quantum::quantum_particle_uncertainty_positive",
        quantum::test_quantum_particle_uncertainty_positive,
    ));
    suite.add(TestCase::new(
        "quantum::quantum_particle_heisenberg_relation",
        quantum::test_quantum_particle_heisenberg_relation,
    ));
    suite.add(TestCase::new(
        "quantum::quantum_particle_timestamp",
        quantum::test_quantum_particle_timestamp,
    ));
    suite.add(TestCase::new(
        "quantum::quantum_particle_debug",
        quantum::test_quantum_particle_debug,
    ));
    suite.add(TestCase::new(
        "quantum::quantum_state_empty_particles",
        quantum::test_quantum_state_empty_particles,
    ));
    suite.add(TestCase::new(
        "quantum::quantum_state_with_particles",
        quantum::test_quantum_state_with_particles,
    ));
    suite.add(TestCase::new(
        "quantum::quantum_state_key_size",
        quantum::test_quantum_state_key_size,
    ));
    suite.add(TestCase::new(
        "quantum::quantum_state_decoherence_timer",
        quantum::test_quantum_state_decoherence_timer,
    ));
    suite.add(TestCase::new("quantum::quantum_state_debug", quantum::test_quantum_state_debug));
    suite.add(TestCase::new(
        "quantum::quantum_state_key_all_zeros",
        quantum::test_quantum_state_key_all_zeros,
    ));
    suite.add(TestCase::new(
        "quantum::quantum_state_key_all_ones",
        quantum::test_quantum_state_key_all_ones,
    ));
    suite.add(TestCase::new(
        "quantum::quantum_particle_superposition",
        quantum::test_quantum_particle_superposition,
    ));
    suite.add(TestCase::new(
        "quantum::quantum_state_multiple_particles",
        quantum::test_quantum_state_multiple_particles,
    ));
    suite.add(TestCase::new(
        "quantum::quantum_particle_all_fields_zero",
        quantum::test_quantum_particle_all_fields_zero,
    ));
    suite.add(TestCase::new(
        "quantum::quantum_state_timer_atomic_operations",
        quantum::test_quantum_state_timer_atomic_operations,
    ));
    suite.add(TestCase::new(
        "quantum::quantum_particle_different_states",
        quantum::test_quantum_particle_different_states,
    ));

    suite.run()
}
