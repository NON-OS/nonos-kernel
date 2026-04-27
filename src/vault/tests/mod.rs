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

mod api;
mod audit;
mod crypto;
mod diag;
mod policy;
mod seal;
mod types;
mod vault_core;

use crate::test::framework::{TestCase, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("vault");

    // API tests (44)
    suite.add(TestCase::new(
        "vault_api_error_not_initialized_eq",
        api::test_vault_api_error_not_initialized_eq,
    ));
    suite.add(TestCase::new(
        "vault_api_error_policy_denied_eq",
        api::test_vault_api_error_policy_denied_eq,
    ));
    suite.add(TestCase::new(
        "vault_api_error_key_not_found_eq",
        api::test_vault_api_error_key_not_found_eq,
    ));
    suite.add(TestCase::new(
        "vault_api_error_seal_failed_eq",
        api::test_vault_api_error_seal_failed_eq,
    ));
    suite.add(TestCase::new(
        "vault_api_error_unseal_failed_eq",
        api::test_vault_api_error_unseal_failed_eq,
    ));
    suite.add(TestCase::new(
        "vault_api_error_invalid_arguments_eq",
        api::test_vault_api_error_invalid_arguments_eq,
    ));
    suite.add(TestCase::new(
        "vault_api_error_internal_error_eq",
        api::test_vault_api_error_internal_error_eq,
    ));
    suite
        .add(TestCase::new("vault_api_error_different_ne", api::test_vault_api_error_different_ne));
    suite.add(TestCase::new("vault_api_error_clone", api::test_vault_api_error_clone));
    suite.add(TestCase::new("vault_api_error_copy", api::test_vault_api_error_copy));
    suite.add(TestCase::new(
        "vault_api_error_debug_not_initialized",
        api::test_vault_api_error_debug_not_initialized,
    ));
    suite.add(TestCase::new(
        "vault_api_error_debug_policy_denied",
        api::test_vault_api_error_debug_policy_denied,
    ));
    suite.add(TestCase::new(
        "vault_api_error_debug_key_not_found",
        api::test_vault_api_error_debug_key_not_found,
    ));
    suite.add(TestCase::new(
        "vault_api_error_debug_seal_failed",
        api::test_vault_api_error_debug_seal_failed,
    ));
    suite.add(TestCase::new(
        "vault_api_error_debug_unseal_failed",
        api::test_vault_api_error_debug_unseal_failed,
    ));
    suite.add(TestCase::new(
        "vault_api_error_debug_invalid_arguments",
        api::test_vault_api_error_debug_invalid_arguments,
    ));
    suite.add(TestCase::new(
        "vault_api_error_debug_internal_error",
        api::test_vault_api_error_debug_internal_error,
    ));
    suite.add(TestCase::new("vault_init_returns_result", api::test_vault_init_returns_result));
    suite.add(TestCase::new("vault_status_returns_bool", api::test_vault_status_returns_bool));
    suite
        .add(TestCase::new("vault_derive_requires_policy", api::test_vault_derive_requires_policy));
    suite.add(TestCase::new("vault_derive_with_policy", api::test_vault_derive_with_policy));
    suite.add(TestCase::new("vault_derive_policy_denied", api::test_vault_derive_policy_denied));
    suite.add(TestCase::new("vault_seal_requires_policy", api::test_vault_seal_requires_policy));
    suite.add(TestCase::new("vault_seal_with_policy", api::test_vault_seal_with_policy));
    suite.add(TestCase::new("vault_seal_policy_denied", api::test_vault_seal_policy_denied));
    suite
        .add(TestCase::new("vault_unseal_requires_policy", api::test_vault_unseal_requires_policy));
    suite.add(TestCase::new("vault_unseal_with_policy", api::test_vault_unseal_with_policy));
    suite.add(TestCase::new("vault_unseal_policy_denied", api::test_vault_unseal_policy_denied));
    suite.add(TestCase::new("vault_erase_requires_policy", api::test_vault_erase_requires_policy));
    suite.add(TestCase::new("vault_erase_with_policy", api::test_vault_erase_with_policy));
    suite.add(TestCase::new("vault_erase_policy_denied", api::test_vault_erase_policy_denied));
    suite.add(TestCase::new("vault_audit_returns_vec", api::test_vault_audit_returns_vec));
    suite.add(TestCase::new(
        "vault_audit_zero_returns_empty",
        api::test_vault_audit_zero_returns_empty,
    ));
    suite.add(TestCase::new(
        "vault_list_policies_returns_vec",
        api::test_vault_list_policies_returns_vec,
    ));
    suite.add(TestCase::new(
        "vault_stats_initialized_field",
        api::test_vault_stats_initialized_field,
    ));
    suite.add(TestCase::new(
        "vault_stats_audit_events_field",
        api::test_vault_stats_audit_events_field,
    ));
    suite.add(TestCase::new("vault_stats_policies_field", api::test_vault_stats_policies_field));
    suite.add(TestCase::new("vault_syscall_dispatch_init", api::test_vault_syscall_dispatch_init));
    suite.add(TestCase::new(
        "vault_syscall_dispatch_derive",
        api::test_vault_syscall_dispatch_derive,
    ));
    suite.add(TestCase::new(
        "vault_syscall_dispatch_seal_returns_invalid",
        api::test_vault_syscall_dispatch_seal_returns_invalid,
    ));
    suite.add(TestCase::new(
        "vault_syscall_dispatch_unseal_returns_invalid",
        api::test_vault_syscall_dispatch_unseal_returns_invalid,
    ));
    suite
        .add(TestCase::new("vault_syscall_dispatch_erase", api::test_vault_syscall_dispatch_erase));
    suite.add(TestCase::new(
        "vault_syscall_dispatch_unknown_op",
        api::test_vault_syscall_dispatch_unknown_op,
    ));
    suite.add(TestCase::new("vault_api_result_ok", api::test_vault_api_result_ok));
    suite.add(TestCase::new("vault_api_result_err", api::test_vault_api_result_err));
    suite.add(TestCase::new(
        "vault_seal_unseal_roundtrip_with_api",
        api::test_vault_seal_unseal_roundtrip_with_api,
    ));

    // Audit tests (24)
    suite.add(TestCase::new("vault_audit_manager_new", audit::test_vault_audit_manager_new));
    suite.add(TestCase::new(
        "vault_audit_manager_log_event",
        audit::test_vault_audit_manager_log_event,
    ));
    suite.add(TestCase::new(
        "vault_audit_manager_recent_returns_reverse_order",
        audit::test_vault_audit_manager_recent_returns_reverse_order,
    ));
    suite.add(TestCase::new(
        "vault_audit_manager_recent_more_than_available",
        audit::test_vault_audit_manager_recent_more_than_available,
    ));
    suite.add(TestCase::new(
        "vault_audit_manager_recent_zero",
        audit::test_vault_audit_manager_recent_zero,
    ));
    suite.add(TestCase::new(
        "vault_audit_manager_filter_by_op",
        audit::test_vault_audit_manager_filter_by_op,
    ));
    suite.add(TestCase::new(
        "vault_audit_manager_filter_by_status",
        audit::test_vault_audit_manager_filter_by_status,
    ));
    suite.add(TestCase::new(
        "vault_audit_manager_filter_by_context",
        audit::test_vault_audit_manager_filter_by_context,
    ));
    suite.add(TestCase::new(
        "vault_audit_manager_filter_combined",
        audit::test_vault_audit_manager_filter_combined,
    ));
    suite.add(TestCase::new(
        "vault_audit_manager_filter_no_match",
        audit::test_vault_audit_manager_filter_no_match,
    ));
    suite.add(TestCase::new(
        "vault_audit_manager_export_all",
        audit::test_vault_audit_manager_export_all,
    ));
    suite.add(TestCase::new(
        "vault_audit_manager_secure_erase",
        audit::test_vault_audit_manager_secure_erase,
    ));
    suite.add(TestCase::new("vault_log_event_api", audit::test_vault_log_event_api));
    suite.add(TestCase::new("vault_audit_recent_api", audit::test_vault_audit_recent_api));
    suite.add(TestCase::new("vault_audit_filter_api", audit::test_vault_audit_filter_api));
    suite.add(TestCase::new(
        "vault_audit_filter_api_with_op",
        audit::test_vault_audit_filter_api_with_op,
    ));
    suite.add(TestCase::new("vault_audit_export_api", audit::test_vault_audit_export_api));
    suite.add(TestCase::new(
        "vault_audit_secure_erase_api",
        audit::test_vault_audit_secure_erase_api,
    ));
    suite.add(TestCase::new(
        "vault_audit_manager_singleton_exists",
        audit::test_vault_audit_manager_singleton_exists,
    ));
    suite.add(TestCase::new(
        "vault_audit_event_timestamp_zero",
        audit::test_vault_audit_event_timestamp_zero,
    ));
    suite.add(TestCase::new(
        "vault_audit_event_timestamp_max",
        audit::test_vault_audit_event_timestamp_max,
    ));
    suite.add(TestCase::new(
        "vault_audit_manager_many_events",
        audit::test_vault_audit_manager_many_events,
    ));
    suite.add(TestCase::new(
        "vault_audit_filter_none_context",
        audit::test_vault_audit_filter_none_context,
    ));
    suite.add(TestCase::new(
        "vault_audit_filter_none_status",
        audit::test_vault_audit_filter_none_status,
    ));

    // Crypto tests (44)
    suite.add(TestCase::new(
        "vault_encrypt_aes_returns_result",
        crypto::test_vault_encrypt_aes_returns_result,
    ));
    suite.add(TestCase::new(
        "vault_decrypt_aes_returns_result",
        crypto::test_vault_decrypt_aes_returns_result,
    ));
    suite.add(TestCase::new("vault_aes_roundtrip", crypto::test_vault_aes_roundtrip));
    suite.add(TestCase::new(
        "vault_encrypt_chacha_returns_result",
        crypto::test_vault_encrypt_chacha_returns_result,
    ));
    suite.add(TestCase::new(
        "vault_decrypt_chacha_returns_result",
        crypto::test_vault_decrypt_chacha_returns_result,
    ));
    suite.add(TestCase::new("vault_chacha_roundtrip", crypto::test_vault_chacha_roundtrip));
    suite.add(TestCase::new(
        "vault_wrap_aes_returns_result",
        crypto::test_vault_wrap_aes_returns_result,
    ));
    suite.add(TestCase::new("vault_unwrap_aes_too_short", crypto::test_vault_unwrap_aes_too_short));
    suite.add(TestCase::new(
        "vault_wrap_unwrap_roundtrip",
        crypto::test_vault_wrap_unwrap_roundtrip,
    ));
    suite.add(TestCase::new(
        "vault_hash_blake3_returns_32_bytes",
        crypto::test_vault_hash_blake3_returns_32_bytes,
    ));
    suite.add(TestCase::new(
        "vault_hash_blake3_deterministic",
        crypto::test_vault_hash_blake3_deterministic,
    ));
    suite.add(TestCase::new(
        "vault_hash_blake3_different_input_different_hash",
        crypto::test_vault_hash_blake3_different_input_different_hash,
    ));
    suite.add(TestCase::new(
        "vault_hash_blake3_empty_input",
        crypto::test_vault_hash_blake3_empty_input,
    ));
    suite.add(TestCase::new(
        "vault_hash_sha256_returns_32_bytes",
        crypto::test_vault_hash_sha256_returns_32_bytes,
    ));
    suite.add(TestCase::new(
        "vault_hash_sha256_deterministic",
        crypto::test_vault_hash_sha256_deterministic,
    ));
    suite.add(TestCase::new(
        "vault_hash_sha256_different_input_different_hash",
        crypto::test_vault_hash_sha256_different_input_different_hash,
    ));
    suite.add(TestCase::new(
        "vault_hash_sha256_empty_input",
        crypto::test_vault_hash_sha256_empty_input,
    ));
    suite.add(TestCase::new(
        "vault_hkdf_expand_returns_result",
        crypto::test_vault_hkdf_expand_returns_result,
    ));
    suite.add(TestCase::new(
        "vault_hkdf_expand_correct_length",
        crypto::test_vault_hkdf_expand_correct_length,
    ));
    suite.add(TestCase::new(
        "vault_hkdf_expand_different_info_different_output",
        crypto::test_vault_hkdf_expand_different_info_different_output,
    ));
    suite.add(TestCase::new(
        "vault_hmac_sha256_returns_32_bytes",
        crypto::test_vault_hmac_sha256_returns_32_bytes,
    ));
    suite.add(TestCase::new(
        "vault_hmac_sha256_deterministic",
        crypto::test_vault_hmac_sha256_deterministic,
    ));
    suite.add(TestCase::new(
        "vault_hmac_sha256_different_key_different_mac",
        crypto::test_vault_hmac_sha256_different_key_different_mac,
    ));
    suite.add(TestCase::new(
        "vault_hmac_sha256_different_data_different_mac",
        crypto::test_vault_hmac_sha256_different_data_different_mac,
    ));
    suite.add(TestCase::new("vault_hmac_verify_valid", crypto::test_vault_hmac_verify_valid));
    suite.add(TestCase::new(
        "vault_hmac_verify_invalid_mac",
        crypto::test_vault_hmac_verify_invalid_mac,
    ));
    suite.add(TestCase::new(
        "vault_hmac_verify_wrong_key",
        crypto::test_vault_hmac_verify_wrong_key,
    ));
    suite.add(TestCase::new(
        "vault_hmac_verify_wrong_data",
        crypto::test_vault_hmac_verify_wrong_data,
    ));
    suite.add(TestCase::new("vault_zeroize", crypto::test_vault_zeroize));
    suite.add(TestCase::new("vault_zeroize_empty", crypto::test_vault_zeroize_empty));
    suite.add(TestCase::new("vault_zeroize_vec", crypto::test_vault_zeroize_vec));
    suite.add(TestCase::new("vault_zeroize_vec_empty", crypto::test_vault_zeroize_vec_empty));
    suite.add(TestCase::new("vault_ct_eq_equal", crypto::test_vault_ct_eq_equal));
    suite.add(TestCase::new("vault_ct_eq_not_equal", crypto::test_vault_ct_eq_not_equal));
    suite.add(TestCase::new(
        "vault_ct_eq_different_length",
        crypto::test_vault_ct_eq_different_length,
    ));
    suite.add(TestCase::new("vault_ct_eq_empty", crypto::test_vault_ct_eq_empty));
    suite.add(TestCase::new("vault_ct_eq_32_equal", crypto::test_vault_ct_eq_32_equal));
    suite.add(TestCase::new("vault_ct_eq_32_not_equal", crypto::test_vault_ct_eq_32_not_equal));
    suite.add(TestCase::new("vault_ct_eq_32_all_zeros", crypto::test_vault_ct_eq_32_all_zeros));
    suite.add(TestCase::new("vault_ct_eq_32_all_ones", crypto::test_vault_ct_eq_32_all_ones));
    suite.add(TestCase::new(
        "vault_kyber_keygen_returns_result",
        crypto::test_vault_kyber_keygen_returns_result,
    ));
    suite.add(TestCase::new(
        "vault_dilithium_keygen_returns_result",
        crypto::test_vault_dilithium_keygen_returns_result,
    ));
    suite.add(TestCase::new(
        "vault_encrypt_aes_empty_plaintext",
        crypto::test_vault_encrypt_aes_empty_plaintext,
    ));
    suite.add(TestCase::new(
        "vault_encrypt_chacha_empty_plaintext",
        crypto::test_vault_encrypt_chacha_empty_plaintext,
    ));
    suite.add(TestCase::new(
        "vault_encrypt_aes_large_plaintext",
        crypto::test_vault_encrypt_aes_large_plaintext,
    ));
    suite.add(TestCase::new(
        "vault_hash_blake3_large_input",
        crypto::test_vault_hash_blake3_large_input,
    ));
    suite.add(TestCase::new(
        "vault_hash_sha256_large_input",
        crypto::test_vault_hash_sha256_large_input,
    ));

    // Diag tests (34)
    suite.add(TestCase::new("vault_health_healthy_eq", diag::test_vault_health_healthy_eq));
    suite.add(TestCase::new(
        "vault_health_uninitialized_eq",
        diag::test_vault_health_uninitialized_eq,
    ));
    suite.add(TestCase::new("vault_health_leaked_eq", diag::test_vault_health_leaked_eq));
    suite.add(TestCase::new(
        "vault_health_policy_violation_eq",
        diag::test_vault_health_policy_violation_eq,
    ));
    suite.add(TestCase::new(
        "vault_health_audit_overflow_eq",
        diag::test_vault_health_audit_overflow_eq,
    ));
    suite.add(TestCase::new("vault_health_unknown_eq", diag::test_vault_health_unknown_eq));
    suite.add(TestCase::new("vault_health_different_ne", diag::test_vault_health_different_ne));
    suite.add(TestCase::new("vault_health_clone", diag::test_vault_health_clone));
    suite.add(TestCase::new("vault_health_copy", diag::test_vault_health_copy));
    suite.add(TestCase::new("vault_health_debug_healthy", diag::test_vault_health_debug_healthy));
    suite.add(TestCase::new(
        "vault_health_debug_uninitialized",
        diag::test_vault_health_debug_uninitialized,
    ));
    suite.add(TestCase::new("vault_health_debug_leaked", diag::test_vault_health_debug_leaked));
    suite.add(TestCase::new(
        "vault_health_debug_policy_violation",
        diag::test_vault_health_debug_policy_violation,
    ));
    suite.add(TestCase::new(
        "vault_health_debug_audit_overflow",
        diag::test_vault_health_debug_audit_overflow,
    ));
    suite.add(TestCase::new("vault_health_debug_unknown", diag::test_vault_health_debug_unknown));
    suite.add(TestCase::new("vault_diagnostics_clone", diag::test_vault_diagnostics_clone));
    suite.add(TestCase::new("vault_diagnostics_debug", diag::test_vault_diagnostics_debug));
    suite.add(TestCase::new(
        "vault_health_check_returns_health",
        diag::test_vault_health_check_returns_health,
    ));
    suite.add(TestCase::new(
        "vault_health_check_uninitialized_when_not_init",
        diag::test_vault_health_check_uninitialized_when_not_init,
    ));
    suite.add(TestCase::new(
        "vault_health_check_detects_policy_violation",
        diag::test_vault_health_check_detects_policy_violation,
    ));
    suite.add(TestCase::new(
        "vault_diagnostics_returns_struct",
        diag::test_vault_diagnostics_returns_struct,
    ));
    suite.add(TestCase::new(
        "vault_diagnostics_health_field",
        diag::test_vault_diagnostics_health_field,
    ));
    suite.add(TestCase::new(
        "vault_diagnostics_audit_recent_field",
        diag::test_vault_diagnostics_audit_recent_field,
    ));
    suite.add(TestCase::new(
        "vault_diagnostics_policy_overview_field",
        diag::test_vault_diagnostics_policy_overview_field,
    ));
    suite.add(TestCase::new(
        "vault_diagnostics_sealed_count_field",
        diag::test_vault_diagnostics_sealed_count_field,
    ));
    suite.add(TestCase::new("vault_leak_scan_returns_vec", diag::test_vault_leak_scan_returns_vec));
    suite.add(TestCase::new(
        "vault_leak_scan_empty_when_no_leaks",
        diag::test_vault_leak_scan_empty_when_no_leaks,
    ));
    suite.add(TestCase::new(
        "vault_policy_violations_returns_vec",
        diag::test_vault_policy_violations_returns_vec,
    ));
    suite.add(TestCase::new(
        "vault_policy_violations_finds_denied",
        diag::test_vault_policy_violations_finds_denied,
    ));
    suite.add(TestCase::new(
        "vault_live_status_returns_string",
        diag::test_vault_live_status_returns_string,
    ));
    suite.add(TestCase::new(
        "vault_live_status_contains_vault_status",
        diag::test_vault_live_status_contains_vault_status,
    ));
    suite.add(TestCase::new(
        "vault_live_status_contains_audit_events",
        diag::test_vault_live_status_contains_audit_events,
    ));
    suite.add(TestCase::new(
        "vault_live_status_contains_policies",
        diag::test_vault_live_status_contains_policies,
    ));
    suite.add(TestCase::new(
        "vault_live_status_contains_sealed_secrets",
        diag::test_vault_live_status_contains_sealed_secrets,
    ));
    suite.add(TestCase::new(
        "vault_diagnostics_after_init",
        diag::test_vault_diagnostics_after_init,
    ));
    suite.add(TestCase::new(
        "vault_diagnostics_after_erase",
        diag::test_vault_diagnostics_after_erase,
    ));
    suite.add(TestCase::new(
        "vault_health_check_multiple_calls",
        diag::test_vault_health_check_multiple_calls,
    ));
    suite.add(TestCase::new(
        "vault_diagnostics_multiple_calls",
        diag::test_vault_diagnostics_multiple_calls,
    ));
    suite.add(TestCase::new(
        "vault_live_status_multiple_calls",
        diag::test_vault_live_status_multiple_calls,
    ));
    suite.add(TestCase::new(
        "vault_policy_violations_with_expired",
        diag::test_vault_policy_violations_with_expired,
    ));
    suite.add(TestCase::new(
        "vault_diagnostics_with_policies",
        diag::test_vault_diagnostics_with_policies,
    ));

    // Policy tests (40)
    suite.add(TestCase::new("vault_capability_read_eq", policy::test_vault_capability_read_eq));
    suite.add(TestCase::new("vault_capability_write_eq", policy::test_vault_capability_write_eq));
    suite.add(TestCase::new("vault_capability_derive_eq", policy::test_vault_capability_derive_eq));
    suite.add(TestCase::new("vault_capability_seal_eq", policy::test_vault_capability_seal_eq));
    suite.add(TestCase::new("vault_capability_unseal_eq", policy::test_vault_capability_unseal_eq));
    suite.add(TestCase::new("vault_capability_audit_eq", policy::test_vault_capability_audit_eq));
    suite.add(TestCase::new("vault_capability_erase_eq", policy::test_vault_capability_erase_eq));
    suite.add(TestCase::new(
        "vault_capability_different_ne",
        policy::test_vault_capability_different_ne,
    ));
    suite.add(TestCase::new("vault_capability_clone", policy::test_vault_capability_clone));
    suite.add(TestCase::new("vault_capability_copy", policy::test_vault_capability_copy));
    suite.add(TestCase::new(
        "vault_capability_debug_read",
        policy::test_vault_capability_debug_read,
    ));
    suite.add(TestCase::new(
        "vault_capability_debug_write",
        policy::test_vault_capability_debug_write,
    ));
    suite.add(TestCase::new(
        "vault_capability_debug_derive",
        policy::test_vault_capability_debug_derive,
    ));
    suite.add(TestCase::new(
        "vault_capability_debug_seal",
        policy::test_vault_capability_debug_seal,
    ));
    suite.add(TestCase::new(
        "vault_capability_debug_unseal",
        policy::test_vault_capability_debug_unseal,
    ));
    suite.add(TestCase::new(
        "vault_capability_debug_audit",
        policy::test_vault_capability_debug_audit,
    ));
    suite.add(TestCase::new(
        "vault_capability_debug_erase",
        policy::test_vault_capability_debug_erase,
    ));
    suite.add(TestCase::new("vault_policy_rule_clone", policy::test_vault_policy_rule_clone));
    suite.add(TestCase::new("vault_policy_rule_debug", policy::test_vault_policy_rule_debug));
    suite.add(TestCase::new(
        "vault_policy_rule_unlimited_uses",
        policy::test_vault_policy_rule_unlimited_uses,
    ));
    suite.add(TestCase::new(
        "vault_policy_rule_limited_uses",
        policy::test_vault_policy_rule_limited_uses,
    ));
    suite.add(TestCase::new(
        "vault_policy_rule_with_expiry",
        policy::test_vault_policy_rule_with_expiry,
    ));
    suite.add(TestCase::new("vault_policy_rule_deny", policy::test_vault_policy_rule_deny));
    suite.add(TestCase::new("vault_policy_engine_new", policy::test_vault_policy_engine_new));
    suite.add(TestCase::new(
        "vault_policy_engine_set_policy",
        policy::test_vault_policy_engine_set_policy,
    ));
    suite.add(TestCase::new(
        "vault_policy_engine_check_allowed",
        policy::test_vault_policy_engine_check_allowed,
    ));
    suite.add(TestCase::new(
        "vault_policy_engine_check_denied",
        policy::test_vault_policy_engine_check_denied,
    ));
    suite.add(TestCase::new(
        "vault_policy_engine_check_no_rule_denies",
        policy::test_vault_policy_engine_check_no_rule_denies,
    ));
    suite.add(TestCase::new(
        "vault_policy_engine_check_wrong_capability_denies",
        policy::test_vault_policy_engine_check_wrong_capability_denies,
    ));
    suite.add(TestCase::new(
        "vault_policy_engine_increment_usage",
        policy::test_vault_policy_engine_increment_usage,
    ));
    suite.add(TestCase::new(
        "vault_policy_engine_max_uses_exceeded",
        policy::test_vault_policy_engine_max_uses_exceeded,
    ));
    suite.add(TestCase::new(
        "vault_policy_engine_clear_policy",
        policy::test_vault_policy_engine_clear_policy,
    ));
    suite.add(TestCase::new(
        "vault_policy_engine_multiple_rules_same_context",
        policy::test_vault_policy_engine_multiple_rules_same_context,
    ));
    suite.add(TestCase::new(
        "vault_policy_engine_update_existing_rule",
        policy::test_vault_policy_engine_update_existing_rule,
    ));
    suite.add(TestCase::new("set_vault_policy_api", policy::test_set_vault_policy_api));
    suite.add(TestCase::new("check_vault_policy_api", policy::test_check_vault_policy_api));
    suite.add(TestCase::new(
        "increment_vault_policy_usage_api",
        policy::test_increment_vault_policy_usage_api,
    ));
    suite.add(TestCase::new("clear_vault_policy_api", policy::test_clear_vault_policy_api));
    suite.add(TestCase::new("list_vault_policies_api", policy::test_list_vault_policies_api));
    suite.add(TestCase::new(
        "vault_policy_engine_singleton_exists",
        policy::test_vault_policy_engine_singleton_exists,
    ));

    // Seal tests (30)
    suite.add(TestCase::new("vault_seal_store_new", seal::test_vault_seal_store_new));
    suite.add(TestCase::new(
        "vault_seal_store_list_sealed_empty",
        seal::test_vault_seal_store_list_sealed_empty,
    ));
    suite.add(TestCase::new(
        "seal_secret_requires_initialization",
        seal::test_seal_secret_requires_initialization,
    ));
    suite.add(TestCase::new(
        "unseal_secret_requires_valid_sealed",
        seal::test_unseal_secret_requires_valid_sealed,
    ));
    suite.add(TestCase::new(
        "seal_unseal_roundtrip_ram_only",
        seal::test_seal_unseal_roundtrip_ram_only,
    ));
    suite.add(TestCase::new(
        "seal_secret_with_empty_plaintext",
        seal::test_seal_secret_with_empty_plaintext,
    ));
    suite.add(TestCase::new("seal_secret_with_empty_aad", seal::test_seal_secret_with_empty_aad));
    suite.add(TestCase::new(
        "seal_secret_with_large_plaintext",
        seal::test_seal_secret_with_large_plaintext,
    ));
    suite.add(TestCase::new("sealed_secret_has_timestamp", seal::test_sealed_secret_has_timestamp));
    suite.add(TestCase::new(
        "sealed_secret_has_audit_event",
        seal::test_sealed_secret_has_audit_event,
    ));
    suite.add(TestCase::new(
        "sealed_secret_preserves_policy",
        seal::test_sealed_secret_preserves_policy,
    ));
    suite.add(TestCase::new("sealed_secret_preserves_aad", seal::test_sealed_secret_preserves_aad));
    suite.add(TestCase::new("list_sealed_returns_vec", seal::test_list_sealed_returns_vec));
    suite.add(TestCase::new("secure_erase_sealed_none", seal::test_secure_erase_sealed_none));
    suite.add(TestCase::new(
        "secure_erase_sealed_ram_only",
        seal::test_secure_erase_sealed_ram_only,
    ));
    suite.add(TestCase::new(
        "seal_policy_ram_only_stays_in_memory",
        seal::test_seal_policy_ram_only_stays_in_memory,
    ));
    suite.add(TestCase::new(
        "multiple_seals_unique_ciphertexts",
        seal::test_multiple_seals_unique_ciphertexts,
    ));
    suite.add(TestCase::new(
        "different_plaintext_different_ciphertext",
        seal::test_different_plaintext_different_ciphertext,
    ));
    suite.add(TestCase::new("seal_secret_logs_audit", seal::test_seal_secret_logs_audit));
    suite.add(TestCase::new("seal_custom_policy", seal::test_seal_custom_policy));
    suite.add(TestCase::new(
        "vault_seal_store_singleton_exists",
        seal::test_vault_seal_store_singleton_exists,
    ));
    suite.add(TestCase::new("seal_secret_api_function", seal::test_seal_secret_api_function));
    suite.add(TestCase::new("unseal_secret_api_function", seal::test_unseal_secret_api_function));
    suite.add(TestCase::new("list_sealed_api_function", seal::test_list_sealed_api_function));
    suite.add(TestCase::new(
        "secure_erase_sealed_api_function",
        seal::test_secure_erase_sealed_api_function,
    ));
    suite.add(TestCase::new("sealed_data_includes_nonce", seal::test_sealed_data_includes_nonce));
    suite.add(TestCase::new("sealed_data_includes_tag", seal::test_sealed_data_includes_tag));
    suite.add(TestCase::new(
        "seal_unseal_preserves_data_integrity",
        seal::test_seal_unseal_preserves_data_integrity,
    ));
    suite.add(TestCase::new("seal_binary_data", seal::test_seal_binary_data));
    suite.add(TestCase::new("seal_all_zeros", seal::test_seal_all_zeros));
    suite.add(TestCase::new("seal_all_ones", seal::test_seal_all_ones));

    // Types tests (17)
    suite.add(TestCase::new("seal_policy_ram_only_eq", types::test_seal_policy_ram_only_eq));
    suite.add(TestCase::new("seal_policy_uefi_eq", types::test_seal_policy_uefi_eq));
    suite.add(TestCase::new("seal_policy_disk_eq", types::test_seal_policy_disk_eq));
    suite.add(TestCase::new("seal_policy_custom_eq", types::test_seal_policy_custom_eq));
    suite.add(TestCase::new(
        "seal_policy_custom_ne_different_backend",
        types::test_seal_policy_custom_ne_different_backend,
    ));
    suite.add(TestCase::new(
        "seal_policy_different_variants_ne",
        types::test_seal_policy_different_variants_ne,
    ));
    suite.add(TestCase::new("seal_policy_clone", types::test_seal_policy_clone));
    suite.add(TestCase::new("seal_policy_custom_clone", types::test_seal_policy_custom_clone));
    suite.add(TestCase::new("seal_policy_debug_ram_only", types::test_seal_policy_debug_ram_only));
    suite.add(TestCase::new("seal_policy_debug_uefi", types::test_seal_policy_debug_uefi));
    suite.add(TestCase::new("seal_policy_debug_disk", types::test_seal_policy_debug_disk));
    suite.add(TestCase::new("seal_policy_debug_custom", types::test_seal_policy_debug_custom));
    suite.add(TestCase::new("sealed_secret_clone", types::test_sealed_secret_clone));
    suite.add(TestCase::new("sealed_secret_debug", types::test_sealed_secret_debug));
    suite.add(TestCase::new("sealed_secret_empty_data", types::test_sealed_secret_empty_data));
    suite.add(TestCase::new("sealed_secret_large_data", types::test_sealed_secret_large_data));
    suite.add(TestCase::new(
        "sealed_secret_with_custom_policy",
        types::test_sealed_secret_with_custom_policy,
    ));
    suite.add(TestCase::new(
        "sealed_secret_audit_event_preserved",
        types::test_sealed_secret_audit_event_preserved,
    ));

    // Vault core tests (3)
    suite.add(TestCase::new("module_exists", vault_core::test_module_exists));
    suite.add(TestCase::new("basic_constants", vault_core::test_basic_constants));
    suite.add(TestCase::new("basic_operations", vault_core::test_basic_operations));

    suite.run()
}
