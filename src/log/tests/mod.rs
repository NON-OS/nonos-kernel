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

pub mod backend;
pub mod entry;
pub mod helpers;
pub mod manager;
pub mod severity;

use crate::test::framework::{TestCase, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("log");

    // Backend tests (28)
    suite.add(TestCase::new("ram_buf_size_constant", backend::test_ram_buf_size_constant));
    suite.add(TestCase::new("ram_buffer_backend_new", backend::test_ram_buffer_backend_new));
    suite.add(TestCase::new(
        "ram_buffer_backend_write_single",
        backend::test_ram_buffer_backend_write_single,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_write_multiple",
        backend::test_ram_buffer_backend_write_multiple,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_get_entries_empty",
        backend::test_ram_buffer_backend_get_entries_empty,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_get_entries_single",
        backend::test_ram_buffer_backend_get_entries_single,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_get_entries_preserves_order",
        backend::test_ram_buffer_backend_get_entries_preserves_order,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_get_recent_empty",
        backend::test_ram_buffer_backend_get_recent_empty,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_get_recent_single",
        backend::test_ram_buffer_backend_get_recent_single,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_get_recent_less_than_requested",
        backend::test_ram_buffer_backend_get_recent_less_than_requested,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_get_recent_exact_count",
        backend::test_ram_buffer_backend_get_recent_exact_count,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_get_recent_returns_newest",
        backend::test_ram_buffer_backend_get_recent_returns_newest,
    ));
    suite.add(TestCase::new("ram_buffer_backend_clear", backend::test_ram_buffer_backend_clear));
    suite.add(TestCase::new(
        "ram_buffer_backend_clear_then_write",
        backend::test_ram_buffer_backend_clear_then_write,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_entry_count_zero",
        backend::test_ram_buffer_backend_entry_count_zero,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_circular_buffer_wrap",
        backend::test_ram_buffer_backend_circular_buffer_wrap,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_circular_buffer_overflow",
        backend::test_ram_buffer_backend_circular_buffer_overflow,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_preserves_entry_data",
        backend::test_ram_buffer_backend_preserves_entry_data,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_const_new",
        backend::test_ram_buffer_backend_const_new,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_get_recent_zero",
        backend::test_ram_buffer_backend_get_recent_zero,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_write_different_severities",
        backend::test_ram_buffer_backend_write_different_severities,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_write_different_cpus",
        backend::test_ram_buffer_backend_write_different_cpus,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_get_entries_after_clear",
        backend::test_ram_buffer_backend_get_entries_after_clear,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_get_recent_after_clear",
        backend::test_ram_buffer_backend_get_recent_after_clear,
    ));
    suite.add(TestCase::new(
        "log_backend_trait_object_safety",
        backend::test_log_backend_trait_object_safety,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_write_message_preserved",
        backend::test_ram_buffer_backend_write_message_preserved,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_multiple_clears",
        backend::test_ram_buffer_backend_multiple_clears,
    ));
    suite.add(TestCase::new(
        "ram_buffer_backend_hash_preserved",
        backend::test_ram_buffer_backend_hash_preserved,
    ));

    // Entry tests (19)
    suite.add(TestCase::new("log_entry_creation", entry::test_log_entry_creation));
    suite.add(TestCase::new("log_entry_with_message", entry::test_log_entry_with_message));
    suite.add(TestCase::new("log_entry_clone", entry::test_log_entry_clone));
    suite.add(TestCase::new("log_entry_timestamp_zero", entry::test_log_entry_timestamp_zero));
    suite.add(TestCase::new("log_entry_timestamp_max", entry::test_log_entry_timestamp_max));
    suite.add(TestCase::new(
        "log_entry_cpu_various_values",
        entry::test_log_entry_cpu_various_values,
    ));
    suite.add(TestCase::new(
        "log_entry_all_severity_levels",
        entry::test_log_entry_all_severity_levels,
    ));
    suite.add(TestCase::new("log_entry_hash_default", entry::test_log_entry_hash_default));
    suite.add(TestCase::new("log_entry_hash_nonzero", entry::test_log_entry_hash_nonzero));
    suite.add(TestCase::new("log_entry_message_empty", entry::test_log_entry_message_empty));
    suite.add(TestCase::new("log_entry_message_long", entry::test_log_entry_message_long));
    suite.add(TestCase::new(
        "log_entry_message_max_capacity",
        entry::test_log_entry_message_max_capacity,
    ));
    suite.add(TestCase::new(
        "log_entry_message_exceeds_capacity",
        entry::test_log_entry_message_exceeds_capacity,
    ));
    suite.add(TestCase::new(
        "log_entry_clone_independence",
        entry::test_log_entry_clone_independence,
    ));
    suite.add(TestCase::new("log_entry_hash_size", entry::test_log_entry_hash_size));
    suite.add(TestCase::new(
        "log_entry_message_push_single_char",
        entry::test_log_entry_message_push_single_char,
    ));
    suite.add(TestCase::new("log_entry_message_unicode", entry::test_log_entry_message_unicode));
    suite.add(TestCase::new(
        "log_entry_multiple_modifications",
        entry::test_log_entry_multiple_modifications,
    ));

    // Helpers tests (24)
    suite.add(TestCase::new(
        "debug_simple_logs_debug_severity",
        helpers::test_debug_simple_logs_debug_severity,
    ));
    suite.add(TestCase::new(
        "info_simple_logs_info_severity",
        helpers::test_info_simple_logs_info_severity,
    ));
    suite.add(TestCase::new(
        "warn_simple_logs_warn_severity",
        helpers::test_warn_simple_logs_warn_severity,
    ));
    suite.add(TestCase::new(
        "log_error_simple_logs_err_severity",
        helpers::test_log_error_simple_logs_err_severity,
    ));
    suite
        .add(TestCase::new("debug_simple_empty_message", helpers::test_debug_simple_empty_message));
    suite.add(TestCase::new("info_simple_empty_message", helpers::test_info_simple_empty_message));
    suite.add(TestCase::new("warn_simple_empty_message", helpers::test_warn_simple_empty_message));
    suite.add(TestCase::new(
        "log_error_simple_empty_message",
        helpers::test_log_error_simple_empty_message,
    ));
    suite.add(TestCase::new("debug_simple_long_message", helpers::test_debug_simple_long_message));
    suite.add(TestCase::new("info_simple_long_message", helpers::test_info_simple_long_message));
    suite.add(TestCase::new("warn_simple_long_message", helpers::test_warn_simple_long_message));
    suite.add(TestCase::new(
        "log_error_simple_long_message",
        helpers::test_log_error_simple_long_message,
    ));
    suite.add(TestCase::new("multiple_helper_calls", helpers::test_multiple_helper_calls));
    suite.add(TestCase::new(
        "helpers_preserve_message_content",
        helpers::test_helpers_preserve_message_content,
    ));
    suite.add(TestCase::new(
        "helpers_no_panic_without_logger",
        helpers::test_helpers_no_panic_without_logger,
    ));
    suite.add(TestCase::new(
        "compat_logger_module_exports",
        helpers::test_compat_logger_module_exports,
    ));
    suite.add(TestCase::new(
        "compat_nonos_logger_module_exports",
        helpers::test_compat_nonos_logger_module_exports,
    ));
    suite.add(TestCase::new(
        "compat_simple_logger_module_exports",
        helpers::test_compat_simple_logger_module_exports,
    ));
    suite.add(TestCase::new("init_logger_alias_exists", helpers::test_init_logger_alias_exists));
    suite.add(TestCase::new(
        "helper_functions_are_inline",
        helpers::test_helper_functions_are_inline,
    ));
    suite.add(TestCase::new(
        "debug_simple_uses_debug_str",
        helpers::test_debug_simple_uses_debug_str,
    ));
    suite.add(TestCase::new("info_simple_uses_info_str", helpers::test_info_simple_uses_info_str));
    suite.add(TestCase::new("warn_simple_uses_warn_str", helpers::test_warn_simple_uses_warn_str));
    suite.add(TestCase::new("error_simple_uses_err_str", helpers::test_error_simple_uses_err_str));

    // Manager tests (40)
    suite.add(TestCase::new("log_manager_new", manager::test_log_manager_new));
    suite.add(TestCase::new("log_manager_const_new", manager::test_log_manager_const_new));
    suite.add(TestCase::new("log_manager_log_single", manager::test_log_manager_log_single));
    suite.add(TestCase::new("log_manager_log_multiple", manager::test_log_manager_log_multiple));
    suite.add(TestCase::new(
        "log_manager_log_all_severities",
        manager::test_log_manager_log_all_severities,
    ));
    suite.add(TestCase::new(
        "log_manager_get_entries_empty",
        manager::test_log_manager_get_entries_empty,
    ));
    suite.add(TestCase::new(
        "log_manager_get_entries_single",
        manager::test_log_manager_get_entries_single,
    ));
    suite.add(TestCase::new(
        "log_manager_get_entries_preserves_message",
        manager::test_log_manager_get_entries_preserves_message,
    ));
    suite.add(TestCase::new(
        "log_manager_get_entries_preserves_severity",
        manager::test_log_manager_get_entries_preserves_severity,
    ));
    suite.add(TestCase::new(
        "log_manager_get_recent_empty",
        manager::test_log_manager_get_recent_empty,
    ));
    suite.add(TestCase::new(
        "log_manager_get_recent_single",
        manager::test_log_manager_get_recent_single,
    ));
    suite.add(TestCase::new(
        "log_manager_get_recent_returns_newest",
        manager::test_log_manager_get_recent_returns_newest,
    ));
    suite.add(TestCase::new(
        "log_manager_get_recent_less_than_available",
        manager::test_log_manager_get_recent_less_than_available,
    ));
    suite.add(TestCase::new(
        "log_manager_entry_count_zero",
        manager::test_log_manager_entry_count_zero,
    ));
    suite.add(TestCase::new(
        "log_manager_entry_count_increments",
        manager::test_log_manager_entry_count_increments,
    ));
    suite.add(TestCase::new("log_manager_clear_buffer", manager::test_log_manager_clear_buffer));
    suite.add(TestCase::new(
        "log_manager_clear_buffer_empty",
        manager::test_log_manager_clear_buffer_empty,
    ));
    suite
        .add(TestCase::new("log_manager_clear_then_log", manager::test_log_manager_clear_then_log));
    suite.add(TestCase::new("log_manager_hash_chain", manager::test_log_manager_hash_chain));
    suite.add(TestCase::new("log_manager_hash_not_zero", manager::test_log_manager_hash_not_zero));
    suite.add(TestCase::new(
        "log_manager_enter_panic_mode",
        manager::test_log_manager_enter_panic_mode,
    ));
    suite.add(TestCase::new("panic_mode_static_default", manager::test_panic_mode_static_default));
    suite.add(TestCase::new(
        "panic_mode_atomic_store_load",
        manager::test_panic_mode_atomic_store_load,
    ));
    suite.add(TestCase::new("log_manager_add_backend", manager::test_log_manager_add_backend));
    suite.add(TestCase::new("log_manager_empty_message", manager::test_log_manager_empty_message));
    suite.add(TestCase::new("log_manager_long_message", manager::test_log_manager_long_message));
    suite.add(TestCase::new(
        "log_manager_message_truncation",
        manager::test_log_manager_message_truncation,
    ));
    suite.add(TestCase::new("logger_static_exists", manager::test_logger_static_exists));
    suite.add(TestCase::new(
        "try_get_logger_returns_some",
        manager::test_try_get_logger_returns_some,
    ));
    suite.add(TestCase::new("log_critical_uses_fatal", manager::test_log_critical_uses_fatal));
    suite.add(TestCase::new("enter_panic_mode_function", manager::test_enter_panic_mode_function));
    suite.add(TestCase::new("get_log_entries_function", manager::test_get_log_entries_function));
    suite.add(TestCase::new("get_recent_logs_function", manager::test_get_recent_logs_function));
    suite.add(TestCase::new("log_entry_count_function", manager::test_log_entry_count_function));
    suite.add(TestCase::new("clear_log_buffer_function", manager::test_clear_log_buffer_function));
    suite
        .add(TestCase::new("log_function_with_severity", manager::test_log_function_with_severity));
    suite.add(TestCase::new(
        "log_manager_timestamps_increase",
        manager::test_log_manager_timestamps_increase,
    ));
    suite.add(TestCase::new("log_manager_cpu_field_set", manager::test_log_manager_cpu_field_set));
    suite.add(TestCase::new(
        "log_manager_hash_deterministic",
        manager::test_log_manager_hash_deterministic,
    ));
    suite.add(TestCase::new(
        "log_manager_different_messages_different_hashes",
        manager::test_log_manager_different_messages_different_hashes,
    ));

    // Severity tests (30)
    suite.add(TestCase::new("severity_debug_variant", severity::test_severity_debug_variant));
    suite.add(TestCase::new("severity_info_variant", severity::test_severity_info_variant));
    suite.add(TestCase::new("severity_warn_variant", severity::test_severity_warn_variant));
    suite.add(TestCase::new("severity_err_variant", severity::test_severity_err_variant));
    suite.add(TestCase::new("severity_fatal_variant", severity::test_severity_fatal_variant));
    suite.add(TestCase::new("severity_debug_color", severity::test_severity_debug_color));
    suite.add(TestCase::new("severity_info_color", severity::test_severity_info_color));
    suite.add(TestCase::new("severity_warn_color", severity::test_severity_warn_color));
    suite.add(TestCase::new("severity_err_color", severity::test_severity_err_color));
    suite.add(TestCase::new("severity_fatal_color", severity::test_severity_fatal_color));
    suite.add(TestCase::new("severity_debug_as_str", severity::test_severity_debug_as_str));
    suite.add(TestCase::new("severity_info_as_str", severity::test_severity_info_as_str));
    suite.add(TestCase::new("severity_warn_as_str", severity::test_severity_warn_as_str));
    suite.add(TestCase::new("severity_err_as_str", severity::test_severity_err_as_str));
    suite.add(TestCase::new("severity_fatal_as_str", severity::test_severity_fatal_as_str));
    suite.add(TestCase::new("severity_clone", severity::test_severity_clone));
    suite.add(TestCase::new("severity_copy", severity::test_severity_copy));
    suite.add(TestCase::new("severity_equality", severity::test_severity_equality));
    suite.add(TestCase::new("severity_inequality", severity::test_severity_inequality));
    suite.add(TestCase::new("severity_debug_format", severity::test_severity_debug_format));
    suite.add(TestCase::new(
        "severity_info_debug_format",
        severity::test_severity_info_debug_format,
    ));
    suite.add(TestCase::new(
        "severity_warn_debug_format",
        severity::test_severity_warn_debug_format,
    ));
    suite.add(TestCase::new("severity_err_debug_format", severity::test_severity_err_debug_format));
    suite.add(TestCase::new(
        "severity_fatal_debug_format",
        severity::test_severity_fatal_debug_format,
    ));
    suite.add(TestCase::new(
        "all_severity_variants_unique",
        severity::test_all_severity_variants_unique,
    ));
    suite.add(TestCase::new(
        "all_severity_str_representations_unique",
        severity::test_all_severity_str_representations_unique,
    ));
    suite.add(TestCase::new(
        "severity_color_returns_valid_color",
        severity::test_severity_color_returns_valid_color,
    ));
    suite.add(TestCase::new("severity_as_str_not_empty", severity::test_severity_as_str_not_empty));
    suite.add(TestCase::new(
        "severity_err_and_fatal_same_color",
        severity::test_severity_err_and_fatal_same_color,
    ));
    suite.add(TestCase::new(
        "severity_debug_info_warn_different_colors",
        severity::test_severity_debug_info_warn_different_colors,
    ));

    suite.run()
}
