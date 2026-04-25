mod cache_tests;
mod dependency_tests;
mod error_tests;
mod extract_tests;
mod hooks_tests;
mod installer_tests;
mod manifest_tests;
mod repository_tests;
mod resolver_tests;
mod sandbox_tests;
mod signature_tests;
mod types_tests;
mod version_tests;

use crate::test::framework::{TestCase, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("npkg");

    // Cache tests (15)
    suite.add(TestCase::new("cache_policy_default", cache_tests::test_cache_policy_default));
    suite.add(TestCase::new("cache_policy_variants", cache_tests::test_cache_policy_variants));
    suite.add(TestCase::new("cache_policy_equality", cache_tests::test_cache_policy_equality));
    suite.add(TestCase::new("cache_policy_inequality", cache_tests::test_cache_policy_inequality));
    suite.add(TestCase::new("cache_policy_copy", cache_tests::test_cache_policy_copy));
    suite.add(TestCase::new("cache_policy_clone", cache_tests::test_cache_policy_clone));
    suite.add(TestCase::new("cache_stats_structure", cache_tests::test_cache_stats_structure));
    suite.add(TestCase::new("cache_stats_clone", cache_tests::test_cache_stats_clone));
    suite
        .add(TestCase::new("cache_stats_debug_format", cache_tests::test_cache_stats_debug_format));
    suite.add(TestCase::new("get_cache_dir", cache_tests::test_get_cache_dir));
    suite.add(TestCase::new(
        "cache_policy_debug_format",
        cache_tests::test_cache_policy_debug_format,
    ));
    suite.add(TestCase::new("cache_stats_empty", cache_tests::test_cache_stats_empty));
    suite
        .add(TestCase::new("cache_stats_large_values", cache_tests::test_cache_stats_large_values));
    suite
        .add(TestCase::new("cache_policy_consistency", cache_tests::test_cache_policy_consistency));
    suite.add(TestCase::new("cache_dir_format", cache_tests::test_cache_dir_format));

    // Dependency tests (22)
    suite.add(TestCase::new("dependency_runtime", dependency_tests::test_dependency_runtime));
    suite.add(TestCase::new(
        "dependency_runtime_with_version",
        dependency_tests::test_dependency_runtime_with_version,
    ));
    suite.add(TestCase::new("dependency_optional", dependency_tests::test_dependency_optional));
    suite.add(TestCase::new("dependency_conflict", dependency_tests::test_dependency_conflict));
    suite.add(TestCase::new(
        "dependency_parse_simple",
        dependency_tests::test_dependency_parse_simple,
    ));
    suite.add(TestCase::new(
        "dependency_parse_with_version_greater_equal",
        dependency_tests::test_dependency_parse_with_version_greater_equal,
    ));
    suite.add(TestCase::new(
        "dependency_parse_with_version_greater",
        dependency_tests::test_dependency_parse_with_version_greater,
    ));
    suite.add(TestCase::new(
        "dependency_parse_with_version_less_equal",
        dependency_tests::test_dependency_parse_with_version_less_equal,
    ));
    suite.add(TestCase::new(
        "dependency_parse_with_version_less",
        dependency_tests::test_dependency_parse_with_version_less,
    ));
    suite.add(TestCase::new(
        "dependency_parse_with_version_exact",
        dependency_tests::test_dependency_parse_with_version_exact,
    ));
    suite.add(TestCase::new(
        "dependency_parse_with_version_compatible",
        dependency_tests::test_dependency_parse_with_version_compatible,
    ));
    suite.add(TestCase::new(
        "dependency_parse_empty",
        dependency_tests::test_dependency_parse_empty,
    ));
    suite.add(TestCase::new(
        "dependency_parse_whitespace_only",
        dependency_tests::test_dependency_parse_whitespace_only,
    ));
    suite.add(TestCase::new(
        "dependency_parse_with_whitespace",
        dependency_tests::test_dependency_parse_with_whitespace,
    ));
    suite.add(TestCase::new("dependency_clone", dependency_tests::test_dependency_clone));
    suite.add(TestCase::new(
        "dependency_kind_variants",
        dependency_tests::test_dependency_kind_variants,
    ));
    suite.add(TestCase::new(
        "dependency_parse_name_with_hyphen",
        dependency_tests::test_dependency_parse_name_with_hyphen,
    ));
    suite.add(TestCase::new(
        "dependency_parse_name_with_underscore",
        dependency_tests::test_dependency_parse_name_with_underscore,
    ));
    suite.add(TestCase::new(
        "version_requirement_equality",
        dependency_tests::test_version_requirement_equality,
    ));
    suite.add(TestCase::new(
        "version_requirement_exact_equality",
        dependency_tests::test_version_requirement_exact_equality,
    ));
    suite.add(TestCase::new(
        "version_requirement_clone",
        dependency_tests::test_version_requirement_clone,
    ));

    // Error tests (40)
    suite.add(TestCase::new(
        "error_package_not_found_message",
        error_tests::test_error_package_not_found_message,
    ));
    suite.add(TestCase::new(
        "error_version_not_found_message",
        error_tests::test_error_version_not_found_message,
    ));
    suite.add(TestCase::new(
        "error_dependency_conflict_message",
        error_tests::test_error_dependency_conflict_message,
    ));
    suite.add(TestCase::new(
        "error_dependency_missing_message",
        error_tests::test_error_dependency_missing_message,
    ));
    suite.add(TestCase::new(
        "error_circular_dependency_message",
        error_tests::test_error_circular_dependency_message,
    ));
    suite.add(TestCase::new(
        "error_checksum_mismatch_message",
        error_tests::test_error_checksum_mismatch_message,
    ));
    suite.add(TestCase::new(
        "error_signature_invalid_message",
        error_tests::test_error_signature_invalid_message,
    ));
    suite.add(TestCase::new(
        "error_signature_key_not_found_message",
        error_tests::test_error_signature_key_not_found_message,
    ));
    suite.add(TestCase::new(
        "error_download_failed_message",
        error_tests::test_error_download_failed_message,
    ));
    suite.add(TestCase::new(
        "error_network_unavailable_message",
        error_tests::test_error_network_unavailable_message,
    ));
    suite.add(TestCase::new(
        "error_repository_not_found_message",
        error_tests::test_error_repository_not_found_message,
    ));
    suite.add(TestCase::new(
        "error_repository_sync_failed_message",
        error_tests::test_error_repository_sync_failed_message,
    ));
    suite.add(TestCase::new(
        "error_manifest_parse_error_message",
        error_tests::test_error_manifest_parse_error_message,
    ));
    suite.add(TestCase::new(
        "error_archive_corrupt_message",
        error_tests::test_error_archive_corrupt_message,
    ));
    suite.add(TestCase::new(
        "error_extraction_failed_message",
        error_tests::test_error_extraction_failed_message,
    ));
    suite.add(TestCase::new(
        "error_installation_failed_message",
        error_tests::test_error_installation_failed_message,
    ));
    suite.add(TestCase::new(
        "error_removal_failed_message",
        error_tests::test_error_removal_failed_message,
    ));
    suite.add(TestCase::new(
        "error_file_conflict_message",
        error_tests::test_error_file_conflict_message,
    ));
    suite.add(TestCase::new(
        "error_permission_denied_message",
        error_tests::test_error_permission_denied_message,
    ));
    suite.add(TestCase::new("error_disk_full_message", error_tests::test_error_disk_full_message));
    suite.add(TestCase::new(
        "error_database_corrupt_message",
        error_tests::test_error_database_corrupt_message,
    ));
    suite.add(TestCase::new(
        "error_database_locked_message",
        error_tests::test_error_database_locked_message,
    ));
    suite.add(TestCase::new("error_io_error_message", error_tests::test_error_io_error_message));
    suite.add(TestCase::new(
        "error_internal_error_message",
        error_tests::test_error_internal_error_message,
    ));
    suite.add(TestCase::new(
        "error_invalid_package_name_message",
        error_tests::test_error_invalid_package_name_message,
    ));
    suite.add(TestCase::new(
        "error_invalid_version_message",
        error_tests::test_error_invalid_version_message,
    ));
    suite.add(TestCase::new(
        "error_hook_failed_message",
        error_tests::test_error_hook_failed_message,
    ));
    suite.add(TestCase::new(
        "error_sandbox_violation_message",
        error_tests::test_error_sandbox_violation_message,
    ));
    suite.add(TestCase::new(
        "error_package_on_hold_message",
        error_tests::test_error_package_on_hold_message,
    ));
    suite.add(TestCase::new(
        "error_already_installed_message",
        error_tests::test_error_already_installed_message,
    ));
    suite.add(TestCase::new(
        "error_not_installed_message",
        error_tests::test_error_not_installed_message,
    ));
    suite.add(TestCase::new(
        "error_upgrade_not_needed_message",
        error_tests::test_error_upgrade_not_needed_message,
    ));
    suite.add(TestCase::new(
        "error_is_recoverable_database_corrupt",
        error_tests::test_error_is_recoverable_database_corrupt,
    ));
    suite.add(TestCase::new(
        "error_is_recoverable_internal_error",
        error_tests::test_error_is_recoverable_internal_error,
    ));
    suite.add(TestCase::new(
        "error_is_recoverable_network_unavailable",
        error_tests::test_error_is_recoverable_network_unavailable,
    ));
    suite.add(TestCase::new(
        "error_is_recoverable_package_not_found",
        error_tests::test_error_is_recoverable_package_not_found,
    ));
    suite.add(TestCase::new(
        "error_is_recoverable_disk_full",
        error_tests::test_error_is_recoverable_disk_full,
    ));
    suite.add(TestCase::new("error_clone", error_tests::test_error_clone));
    suite.add(TestCase::new("npkg_result_ok", error_tests::test_npkg_result_ok));
    suite.add(TestCase::new("npkg_result_err", error_tests::test_npkg_result_err));

    // Extract tests (40)
    suite.add(TestCase::new("npkg_magic_constant", extract_tests::test_npkg_magic_constant));
    suite.add(TestCase::new(
        "npkg_magic_is_npkg_ascii",
        extract_tests::test_npkg_magic_is_npkg_ascii,
    ));
    suite.add(TestCase::new("npkg_version_constant", extract_tests::test_npkg_version_constant));
    suite.add(TestCase::new("entry_file_constant", extract_tests::test_entry_file_constant));
    suite.add(TestCase::new("entry_dir_constant", extract_tests::test_entry_dir_constant));
    suite.add(TestCase::new("entry_symlink_constant", extract_tests::test_entry_symlink_constant));
    suite.add(TestCase::new("entry_types_unique", extract_tests::test_entry_types_unique));
    suite.add(TestCase::new("archive_entry_file", extract_tests::test_archive_entry_file));
    suite.add(TestCase::new("archive_entry_dir", extract_tests::test_archive_entry_dir));
    suite.add(TestCase::new("archive_entry_symlink", extract_tests::test_archive_entry_symlink));
    suite.add(TestCase::new("archive_entry_path", extract_tests::test_archive_entry_path));
    suite.add(TestCase::new("archive_entry_size", extract_tests::test_archive_entry_size));
    suite.add(TestCase::new(
        "archive_entry_large_size",
        extract_tests::test_archive_entry_large_size,
    ));
    suite.add(TestCase::new(
        "archive_entry_mode_executable",
        extract_tests::test_archive_entry_mode_executable,
    ));
    suite.add(TestCase::new(
        "archive_entry_mode_readonly",
        extract_tests::test_archive_entry_mode_readonly,
    ));
    suite.add(TestCase::new("archive_entry_checksum", extract_tests::test_archive_entry_checksum));
    suite.add(TestCase::new(
        "archive_entry_checksum_unique",
        extract_tests::test_archive_entry_checksum_unique,
    ));
    suite.add(TestCase::new(
        "archive_entry_data_offset",
        extract_tests::test_archive_entry_data_offset,
    ));
    suite.add(TestCase::new(
        "archive_entry_data_offset_large",
        extract_tests::test_archive_entry_data_offset_large,
    ));
    suite.add(TestCase::new("archive_entry_clone", extract_tests::test_archive_entry_clone));
    suite.add(TestCase::new(
        "archive_entry_clone_with_symlink",
        extract_tests::test_archive_entry_clone_with_symlink,
    ));
    suite.add(TestCase::new("archive_entry_debug", extract_tests::test_archive_entry_debug));
    suite.add(TestCase::new(
        "archive_entry_empty_path",
        extract_tests::test_archive_entry_empty_path,
    ));
    suite
        .add(TestCase::new("archive_entry_deep_path", extract_tests::test_archive_entry_deep_path));
    suite.add(TestCase::new(
        "archive_entry_unicode_path",
        extract_tests::test_archive_entry_unicode_path,
    ));
    suite.add(TestCase::new(
        "archive_entry_zero_size_file",
        extract_tests::test_archive_entry_zero_size_file,
    ));
    suite.add(TestCase::new(
        "archive_entry_mode_all_permissions",
        extract_tests::test_archive_entry_mode_all_permissions,
    ));
    suite.add(TestCase::new(
        "archive_entry_mode_no_permissions",
        extract_tests::test_archive_entry_mode_no_permissions,
    ));
    suite.add(TestCase::new(
        "archive_entry_setuid_mode",
        extract_tests::test_archive_entry_setuid_mode,
    ));
    suite.add(TestCase::new(
        "archive_entry_setgid_mode",
        extract_tests::test_archive_entry_setgid_mode,
    ));
    suite.add(TestCase::new(
        "archive_entry_sticky_bit",
        extract_tests::test_archive_entry_sticky_bit,
    ));
    suite.add(TestCase::new(
        "archive_entry_relative_symlink",
        extract_tests::test_archive_entry_relative_symlink,
    ));
    suite.add(TestCase::new(
        "archive_entry_absolute_symlink",
        extract_tests::test_archive_entry_absolute_symlink,
    ));
    suite.add(TestCase::new(
        "archive_entry_empty_symlink_target",
        extract_tests::test_archive_entry_empty_symlink_target,
    ));
    suite.add(TestCase::new("entry_type_is_file", extract_tests::test_entry_type_is_file));
    suite.add(TestCase::new("entry_type_is_dir", extract_tests::test_entry_type_is_dir));
    suite.add(TestCase::new("entry_type_is_symlink", extract_tests::test_entry_type_is_symlink));
    suite.add(TestCase::new(
        "archive_entry_typical_binary",
        extract_tests::test_archive_entry_typical_binary,
    ));
    suite.add(TestCase::new(
        "archive_entry_typical_config",
        extract_tests::test_archive_entry_typical_config,
    ));
    suite.add(TestCase::new(
        "archive_entry_typical_library",
        extract_tests::test_archive_entry_typical_library,
    ));
    suite.add(TestCase::new(
        "archive_entry_library_symlink",
        extract_tests::test_archive_entry_library_symlink,
    ));
    suite.add(TestCase::new("npkg_magic_nonzero", extract_tests::test_npkg_magic_nonzero));
    suite.add(TestCase::new("npkg_version_positive", extract_tests::test_npkg_version_positive));
    suite.add(TestCase::new(
        "entry_constants_fit_in_u8",
        extract_tests::test_entry_constants_fit_in_u8,
    ));

    // Hooks tests (21)
    suite.add(TestCase::new(
        "pre_install_hook_structure",
        hooks_tests::test_pre_install_hook_structure,
    ));
    suite.add(TestCase::new(
        "post_install_hook_structure",
        hooks_tests::test_post_install_hook_structure,
    ));
    suite.add(TestCase::new(
        "pre_remove_hook_structure",
        hooks_tests::test_pre_remove_hook_structure,
    ));
    suite.add(TestCase::new(
        "post_remove_hook_structure",
        hooks_tests::test_post_remove_hook_structure,
    ));
    suite.add(TestCase::new("hook_clone", hooks_tests::test_hook_clone));
    suite.add(TestCase::new("post_install_hook_clone", hooks_tests::test_post_install_hook_clone));
    suite.add(TestCase::new("pre_remove_hook_clone", hooks_tests::test_pre_remove_hook_clone));
    suite.add(TestCase::new("post_remove_hook_clone", hooks_tests::test_post_remove_hook_clone));
    suite.add(TestCase::new(
        "run_pre_install_empty_script",
        hooks_tests::test_run_pre_install_empty_script,
    ));
    suite.add(TestCase::new(
        "run_post_install_empty_script",
        hooks_tests::test_run_post_install_empty_script,
    ));
    suite.add(TestCase::new(
        "run_pre_remove_empty_script",
        hooks_tests::test_run_pre_remove_empty_script,
    ));
    suite.add(TestCase::new(
        "run_post_remove_empty_script",
        hooks_tests::test_run_post_remove_empty_script,
    ));
    suite.add(TestCase::new("hook_with_comment", hooks_tests::test_hook_with_comment));
    suite.add(TestCase::new("hook_with_empty_lines", hooks_tests::test_hook_with_empty_lines));
    suite.add(TestCase::new("hook_script_echo", hooks_tests::test_hook_script_echo));
    suite.add(TestCase::new("hook_debug_format", hooks_tests::test_hook_debug_format));
    suite.add(TestCase::new(
        "post_install_hook_debug_format",
        hooks_tests::test_post_install_hook_debug_format,
    ));
    suite.add(TestCase::new(
        "pre_remove_hook_debug_format",
        hooks_tests::test_pre_remove_hook_debug_format,
    ));
    suite.add(TestCase::new(
        "post_remove_hook_debug_format",
        hooks_tests::test_post_remove_hook_debug_format,
    ));

    // Installer tests (24)
    suite.add(TestCase::new(
        "install_options_default",
        installer_tests::test_install_options_default,
    ));
    suite.add(TestCase::new("install_options_clone", installer_tests::test_install_options_clone));
    suite.add(TestCase::new(
        "install_options_debug_format",
        installer_tests::test_install_options_debug_format,
    ));
    suite.add(TestCase::new("install_options_force", installer_tests::test_install_options_force));
    suite.add(TestCase::new(
        "install_options_no_deps",
        installer_tests::test_install_options_no_deps,
    ));
    suite.add(TestCase::new(
        "install_options_no_scripts",
        installer_tests::test_install_options_no_scripts,
    ));
    suite.add(TestCase::new(
        "install_options_download_only",
        installer_tests::test_install_options_download_only,
    ));
    suite.add(TestCase::new(
        "install_options_as_dependency",
        installer_tests::test_install_options_as_dependency,
    ));
    suite.add(TestCase::new(
        "install_options_reinstall",
        installer_tests::test_install_options_reinstall,
    ));
    suite
        .add(TestCase::new("remove_options_default", installer_tests::test_remove_options_default));
    suite.add(TestCase::new("remove_options_clone", installer_tests::test_remove_options_clone));
    suite.add(TestCase::new(
        "remove_options_debug_format",
        installer_tests::test_remove_options_debug_format,
    ));
    suite.add(TestCase::new(
        "remove_options_recursive",
        installer_tests::test_remove_options_recursive,
    ));
    suite.add(TestCase::new(
        "remove_options_no_scripts",
        installer_tests::test_remove_options_no_scripts,
    ));
    suite.add(TestCase::new(
        "remove_options_keep_config",
        installer_tests::test_remove_options_keep_config,
    ));
    suite.add(TestCase::new("remove_options_purge", installer_tests::test_remove_options_purge));
    suite.add(TestCase::new(
        "upgrade_options_default",
        installer_tests::test_upgrade_options_default,
    ));
    suite.add(TestCase::new("upgrade_options_clone", installer_tests::test_upgrade_options_clone));
    suite.add(TestCase::new(
        "upgrade_options_debug_format",
        installer_tests::test_upgrade_options_debug_format,
    ));
    suite.add(TestCase::new(
        "upgrade_options_no_deps",
        installer_tests::test_upgrade_options_no_deps,
    ));
    suite.add(TestCase::new(
        "upgrade_options_no_scripts",
        installer_tests::test_upgrade_options_no_scripts,
    ));
    suite.add(TestCase::new(
        "upgrade_options_download_only",
        installer_tests::test_upgrade_options_download_only,
    ));
    suite.add(TestCase::new(
        "install_options_all_true",
        installer_tests::test_install_options_all_true,
    ));
    suite.add(TestCase::new(
        "remove_options_all_true",
        installer_tests::test_remove_options_all_true,
    ));
    suite.add(TestCase::new(
        "upgrade_options_all_true",
        installer_tests::test_upgrade_options_all_true,
    ));

    // Manifest tests (35)
    suite.add(TestCase::new("manifest_builder_new", manifest_tests::test_manifest_builder_new));
    suite.add(TestCase::new(
        "manifest_builder_missing_name",
        manifest_tests::test_manifest_builder_missing_name,
    ));
    suite.add(TestCase::new(
        "manifest_builder_missing_version",
        manifest_tests::test_manifest_builder_missing_version,
    ));
    suite.add(TestCase::new("manifest_builder_full", manifest_tests::test_manifest_builder_full));
    suite.add(TestCase::new(
        "manifest_builder_default_license",
        manifest_tests::test_manifest_builder_default_license,
    ));
    suite.add(TestCase::new(
        "manifest_builder_with_dependency",
        manifest_tests::test_manifest_builder_with_dependency,
    ));
    suite.add(TestCase::new(
        "manifest_builder_with_install_script",
        manifest_tests::test_manifest_builder_with_install_script,
    ));
    suite.add(TestCase::new(
        "manifest_builder_with_remove_script",
        manifest_tests::test_manifest_builder_with_remove_script,
    ));
    suite.add(TestCase::new(
        "manifest_builder_default",
        manifest_tests::test_manifest_builder_default,
    ));
    suite.add(TestCase::new("parse_manifest_simple", manifest_tests::test_parse_manifest_simple));
    suite.add(TestCase::new(
        "parse_manifest_with_quotes",
        manifest_tests::test_parse_manifest_with_quotes,
    ));
    suite.add(TestCase::new(
        "parse_manifest_missing_name",
        manifest_tests::test_parse_manifest_missing_name,
    ));
    suite.add(TestCase::new(
        "parse_manifest_missing_version",
        manifest_tests::test_parse_manifest_missing_version,
    ));
    suite.add(TestCase::new(
        "parse_manifest_with_comments",
        manifest_tests::test_parse_manifest_with_comments,
    ));
    suite.add(TestCase::new(
        "parse_manifest_with_empty_lines",
        manifest_tests::test_parse_manifest_with_empty_lines,
    ));
    suite.add(TestCase::new(
        "parse_manifest_with_architecture",
        manifest_tests::test_parse_manifest_with_architecture,
    ));
    suite.add(TestCase::new(
        "parse_manifest_with_arch_shorthand",
        manifest_tests::test_parse_manifest_with_arch_shorthand,
    ));
    suite.add(TestCase::new(
        "parse_manifest_with_kind",
        manifest_tests::test_parse_manifest_with_kind,
    ));
    suite.add(TestCase::new(
        "parse_manifest_with_type_shorthand",
        manifest_tests::test_parse_manifest_with_type_shorthand,
    ));
    suite.add(TestCase::new(
        "parse_manifest_with_dependencies",
        manifest_tests::test_parse_manifest_with_dependencies,
    ));
    suite.add(TestCase::new(
        "parse_manifest_with_optional_dependency",
        manifest_tests::test_parse_manifest_with_optional_dependency,
    ));
    suite.add(TestCase::new(
        "parse_manifest_with_conflict",
        manifest_tests::test_parse_manifest_with_conflict,
    ));
    suite.add(TestCase::new(
        "parse_manifest_with_files",
        manifest_tests::test_parse_manifest_with_files,
    ));
    suite.add(TestCase::new(
        "parse_manifest_file_executable",
        manifest_tests::test_parse_manifest_file_executable,
    ));
    suite.add(TestCase::new(
        "parse_manifest_file_config",
        manifest_tests::test_parse_manifest_file_config,
    ));
    suite.add(TestCase::new(
        "parse_manifest_file_directory",
        manifest_tests::test_parse_manifest_file_directory,
    ));
    suite.add(TestCase::new(
        "parse_manifest_with_install_section",
        manifest_tests::test_parse_manifest_with_install_section,
    ));
    suite.add(TestCase::new(
        "parse_manifest_with_remove_section",
        manifest_tests::test_parse_manifest_with_remove_section,
    ));
    suite.add(TestCase::new(
        "parse_manifest_invalid_utf8",
        manifest_tests::test_parse_manifest_invalid_utf8,
    ));
    suite.add(TestCase::new(
        "serialize_manifest_simple",
        manifest_tests::test_serialize_manifest_simple,
    ));
    suite.add(TestCase::new("serialize_then_parse", manifest_tests::test_serialize_then_parse));
    suite.add(TestCase::new("manifest_raw_bytes", manifest_tests::test_manifest_raw_bytes));
    suite.add(TestCase::new("manifest_new", manifest_tests::test_manifest_new));

    // Repository tests (19)
    suite.add(TestCase::new(
        "repository_kind_official_trust_level",
        repository_tests::test_repository_kind_official_trust_level,
    ));
    suite.add(TestCase::new(
        "repository_kind_community_trust_level",
        repository_tests::test_repository_kind_community_trust_level,
    ));
    suite.add(TestCase::new(
        "repository_kind_thirdparty_trust_level",
        repository_tests::test_repository_kind_thirdparty_trust_level,
    ));
    suite.add(TestCase::new(
        "repository_kind_local_trust_level",
        repository_tests::test_repository_kind_local_trust_level,
    ));
    suite.add(TestCase::new(
        "repository_kind_variants",
        repository_tests::test_repository_kind_variants,
    ));
    suite.add(TestCase::new(
        "repository_kind_equality",
        repository_tests::test_repository_kind_equality,
    ));
    suite.add(TestCase::new("repository_kind_copy", repository_tests::test_repository_kind_copy));
    suite.add(TestCase::new("repository_kind_clone", repository_tests::test_repository_kind_clone));
    suite.add(TestCase::new(
        "repository_kind_debug_format",
        repository_tests::test_repository_kind_debug_format,
    ));
    suite.add(TestCase::new(
        "repository_config_official",
        repository_tests::test_repository_config_official,
    ));
    suite.add(TestCase::new(
        "repository_config_community",
        repository_tests::test_repository_config_community,
    ));
    suite.add(TestCase::new(
        "repository_config_local",
        repository_tests::test_repository_config_local,
    ));
    suite.add(TestCase::new(
        "repository_config_clone",
        repository_tests::test_repository_config_clone,
    ));
    suite.add(TestCase::new(
        "repository_config_debug_format",
        repository_tests::test_repository_config_debug_format,
    ));
    suite.add(TestCase::new(
        "repository_config_priority_ordering",
        repository_tests::test_repository_config_priority_ordering,
    ));
    suite.add(TestCase::new(
        "repository_config_signature_policy",
        repository_tests::test_repository_config_signature_policy,
    ));
    suite.add(TestCase::new(
        "repository_config_enabled_by_default",
        repository_tests::test_repository_config_enabled_by_default,
    ));
    suite.add(TestCase::new("list_repositories", repository_tests::test_list_repositories));
    suite.add(TestCase::new(
        "repository_kind_trust_ordering",
        repository_tests::test_repository_kind_trust_ordering,
    ));
    suite.add(TestCase::new(
        "repository_config_with_https",
        repository_tests::test_repository_config_with_https,
    ));
    suite.add(TestCase::new(
        "repository_config_local_path_absolute",
        repository_tests::test_repository_config_local_path_absolute,
    ));

    // Resolver tests (37)
    suite.add(TestCase::new("resolution_result_new", resolver_tests::test_resolution_result_new));
    suite.add(TestCase::new(
        "resolution_result_is_empty_true",
        resolver_tests::test_resolution_result_is_empty_true,
    ));
    suite.add(TestCase::new(
        "resolution_result_is_empty_with_install",
        resolver_tests::test_resolution_result_is_empty_with_install,
    ));
    suite.add(TestCase::new(
        "resolution_result_is_empty_with_upgrade",
        resolver_tests::test_resolution_result_is_empty_with_upgrade,
    ));
    suite.add(TestCase::new(
        "resolution_result_is_empty_with_remove",
        resolver_tests::test_resolution_result_is_empty_with_remove,
    ));
    suite.add(TestCase::new(
        "resolution_result_total_packages_empty",
        resolver_tests::test_resolution_result_total_packages_empty,
    ));
    suite.add(TestCase::new(
        "resolution_result_total_packages_with_install",
        resolver_tests::test_resolution_result_total_packages_with_install,
    ));
    suite.add(TestCase::new(
        "resolution_result_total_packages_with_upgrade",
        resolver_tests::test_resolution_result_total_packages_with_upgrade,
    ));
    suite.add(TestCase::new(
        "resolution_result_total_packages_combined",
        resolver_tests::test_resolution_result_total_packages_combined,
    ));
    suite.add(TestCase::new(
        "resolution_result_total_packages_ignores_remove",
        resolver_tests::test_resolution_result_total_packages_ignores_remove,
    ));
    suite.add(TestCase::new(
        "resolution_result_clone",
        resolver_tests::test_resolution_result_clone,
    ));
    suite.add(TestCase::new(
        "resolution_result_with_satisfied",
        resolver_tests::test_resolution_result_with_satisfied,
    ));
    suite.add(TestCase::new(
        "resolution_result_with_optional",
        resolver_tests::test_resolution_result_with_optional,
    ));
    suite.add(TestCase::new(
        "resolution_result_install_reasons",
        resolver_tests::test_resolution_result_install_reasons,
    ));
    suite.add(TestCase::new("resolution_plan_fields", resolver_tests::test_resolution_plan_fields));
    suite.add(TestCase::new(
        "resolution_plan_empty_result",
        resolver_tests::test_resolution_plan_empty_result,
    ));
    suite.add(TestCase::new(
        "resolution_plan_with_installs",
        resolver_tests::test_resolution_plan_with_installs,
    ));
    suite.add(TestCase::new(
        "resolution_plan_with_removes",
        resolver_tests::test_resolution_plan_with_removes,
    ));
    suite.add(TestCase::new("resolution_plan_clone", resolver_tests::test_resolution_plan_clone));
    suite.add(TestCase::new(
        "resolution_plan_large_sizes",
        resolver_tests::test_resolution_plan_large_sizes,
    ));
    suite.add(TestCase::new(
        "resolution_plan_net_size_increase",
        resolver_tests::test_resolution_plan_net_size_increase,
    ));
    suite.add(TestCase::new(
        "resolution_plan_net_size_decrease",
        resolver_tests::test_resolution_plan_net_size_decrease,
    ));
    suite.add(TestCase::new(
        "install_reason_explicit",
        resolver_tests::test_install_reason_explicit,
    ));
    suite.add(TestCase::new(
        "install_reason_dependency",
        resolver_tests::test_install_reason_dependency,
    ));
    suite.add(TestCase::new(
        "install_reason_optional",
        resolver_tests::test_install_reason_optional,
    ));
    suite.add(TestCase::new("install_reason_clone", resolver_tests::test_install_reason_clone));
    suite.add(TestCase::new("install_reason_copy", resolver_tests::test_install_reason_copy));
    suite.add(TestCase::new(
        "install_reason_equality",
        resolver_tests::test_install_reason_equality,
    ));
    suite.add(TestCase::new(
        "resolution_result_multiple_satisfied",
        resolver_tests::test_resolution_result_multiple_satisfied,
    ));
    suite.add(TestCase::new(
        "resolution_result_complex_scenario",
        resolver_tests::test_resolution_result_complex_scenario,
    ));
    suite.add(TestCase::new(
        "resolution_result_debug",
        resolver_tests::test_resolution_result_debug,
    ));
    suite.add(TestCase::new("resolution_plan_debug", resolver_tests::test_resolution_plan_debug));
    suite.add(TestCase::new(
        "resolution_result_upgrade_versions",
        resolver_tests::test_resolution_result_upgrade_versions,
    ));
    suite.add(TestCase::new(
        "resolution_plan_access_inner_result",
        resolver_tests::test_resolution_plan_access_inner_result,
    ));
    suite.add(TestCase::new(
        "resolution_result_empty_strings",
        resolver_tests::test_resolution_result_empty_strings,
    ));
    suite.add(TestCase::new(
        "resolution_plan_zero_download_nonzero_install",
        resolver_tests::test_resolution_plan_zero_download_nonzero_install,
    ));

    // Sandbox tests (37)
    suite.add(TestCase::new("sandbox_config_default", sandbox_tests::test_sandbox_config_default));
    suite.add(TestCase::new(
        "sandbox_config_default_allowed_paths",
        sandbox_tests::test_sandbox_config_default_allowed_paths,
    ));
    suite.add(TestCase::new(
        "sandbox_config_default_denied_paths",
        sandbox_tests::test_sandbox_config_default_denied_paths,
    ));
    suite.add(TestCase::new(
        "sandbox_config_permissive",
        sandbox_tests::test_sandbox_config_permissive,
    ));
    suite.add(TestCase::new(
        "sandbox_config_restrictive",
        sandbox_tests::test_sandbox_config_restrictive,
    ));
    suite.add(TestCase::new(
        "sandbox_config_is_path_allowed_usr",
        sandbox_tests::test_sandbox_config_is_path_allowed_usr,
    ));
    suite.add(TestCase::new(
        "sandbox_config_is_path_allowed_opt",
        sandbox_tests::test_sandbox_config_is_path_allowed_opt,
    ));
    suite.add(TestCase::new(
        "sandbox_config_is_path_allowed_etc",
        sandbox_tests::test_sandbox_config_is_path_allowed_etc,
    ));
    suite.add(TestCase::new(
        "sandbox_config_is_path_denied_boot",
        sandbox_tests::test_sandbox_config_is_path_denied_boot,
    ));
    suite.add(TestCase::new(
        "sandbox_config_is_path_denied_dev",
        sandbox_tests::test_sandbox_config_is_path_denied_dev,
    ));
    suite.add(TestCase::new(
        "sandbox_config_is_path_denied_proc",
        sandbox_tests::test_sandbox_config_is_path_denied_proc,
    ));
    suite.add(TestCase::new(
        "sandbox_config_is_path_denied_sys",
        sandbox_tests::test_sandbox_config_is_path_denied_sys,
    ));
    suite.add(TestCase::new(
        "sandbox_config_is_path_denied_root",
        sandbox_tests::test_sandbox_config_is_path_denied_root,
    ));
    suite.add(TestCase::new(
        "sandbox_config_permissive_allows_all",
        sandbox_tests::test_sandbox_config_permissive_allows_all,
    ));
    suite.add(TestCase::new(
        "sandbox_config_restrictive_limited_paths",
        sandbox_tests::test_sandbox_config_restrictive_limited_paths,
    ));
    suite.add(TestCase::new("sandbox_config_clone", sandbox_tests::test_sandbox_config_clone));
    suite.add(TestCase::new(
        "sandbox_config_debug_format",
        sandbox_tests::test_sandbox_config_debug_format,
    ));
    suite.add(TestCase::new(
        "sandboxed_install_structure",
        sandbox_tests::test_sandboxed_install_structure,
    ));
    suite.add(TestCase::new(
        "sandboxed_install_check_path_allowed",
        sandbox_tests::test_sandboxed_install_check_path_allowed,
    ));
    suite.add(TestCase::new(
        "sandboxed_install_check_path_denied",
        sandbox_tests::test_sandboxed_install_check_path_denied,
    ));
    suite.add(TestCase::new(
        "sandboxed_install_records_violation",
        sandbox_tests::test_sandboxed_install_records_violation,
    ));
    suite.add(TestCase::new(
        "sandboxed_install_check_memory_within_limit",
        sandbox_tests::test_sandboxed_install_check_memory_within_limit,
    ));
    suite.add(TestCase::new(
        "sandboxed_install_check_memory_exceeds_limit",
        sandbox_tests::test_sandboxed_install_check_memory_exceeds_limit,
    ));
    suite.add(TestCase::new(
        "sandboxed_install_check_file_count_within_limit",
        sandbox_tests::test_sandboxed_install_check_file_count_within_limit,
    ));
    suite.add(TestCase::new(
        "sandboxed_install_check_file_count_exceeds_limit",
        sandbox_tests::test_sandboxed_install_check_file_count_exceeds_limit,
    ));
    suite.add(TestCase::new(
        "sandboxed_install_record_file",
        sandbox_tests::test_sandboxed_install_record_file,
    ));
    suite.add(TestCase::new(
        "sandboxed_install_multiple_files",
        sandbox_tests::test_sandboxed_install_multiple_files,
    ));
    suite.add(TestCase::new(
        "verify_sandbox_integrity_empty",
        sandbox_tests::test_verify_sandbox_integrity_empty,
    ));
    suite.add(TestCase::new(
        "sandbox_config_max_memory_values",
        sandbox_tests::test_sandbox_config_max_memory_values,
    ));
    suite.add(TestCase::new(
        "sandbox_config_max_files_values",
        sandbox_tests::test_sandbox_config_max_files_values,
    ));
    suite.add(TestCase::new(
        "sandbox_config_timeout_values",
        sandbox_tests::test_sandbox_config_timeout_values,
    ));
    suite.add(TestCase::new(
        "sandboxed_install_check_timeout",
        sandbox_tests::test_sandboxed_install_check_timeout,
    ));

    // Signature tests (27)
    suite.add(TestCase::new(
        "signature_size_constant",
        signature_tests::test_signature_size_constant,
    ));
    suite.add(TestCase::new(
        "public_key_size_constant",
        signature_tests::test_public_key_size_constant,
    ));
    suite.add(TestCase::new(
        "secret_key_size_constant",
        signature_tests::test_secret_key_size_constant,
    ));
    suite.add(TestCase::new(
        "package_signature_from_bytes_valid",
        signature_tests::test_package_signature_from_bytes_valid,
    ));
    suite.add(TestCase::new(
        "package_signature_from_bytes_too_short",
        signature_tests::test_package_signature_from_bytes_too_short,
    ));
    suite.add(TestCase::new(
        "package_signature_from_bytes_exact_minimum",
        signature_tests::test_package_signature_from_bytes_exact_minimum,
    ));
    suite.add(TestCase::new(
        "package_signature_to_bytes",
        signature_tests::test_package_signature_to_bytes,
    ));
    suite.add(TestCase::new(
        "package_signature_roundtrip",
        signature_tests::test_package_signature_roundtrip,
    ));
    suite.add(TestCase::new(
        "package_signature_clone",
        signature_tests::test_package_signature_clone,
    ));
    suite.add(TestCase::new(
        "package_signature_debug_format",
        signature_tests::test_package_signature_debug_format,
    ));
    suite.add(TestCase::new(
        "verifying_key_from_bytes_valid",
        signature_tests::test_verifying_key_from_bytes_valid,
    ));
    suite.add(TestCase::new(
        "verifying_key_from_bytes_too_short",
        signature_tests::test_verifying_key_from_bytes_too_short,
    ));
    suite.add(TestCase::new(
        "verifying_key_from_bytes_too_long",
        signature_tests::test_verifying_key_from_bytes_too_long,
    ));
    suite.add(TestCase::new("verifying_key_key_id", signature_tests::test_verifying_key_key_id));
    suite.add(TestCase::new("verifying_key_clone", signature_tests::test_verifying_key_clone));
    suite.add(TestCase::new(
        "verifying_key_debug_format",
        signature_tests::test_verifying_key_debug_format,
    ));
    suite.add(TestCase::new(
        "generate_signing_keypair",
        signature_tests::test_generate_signing_keypair,
    ));
    suite
        .add(TestCase::new("signing_key_public_key", signature_tests::test_signing_key_public_key));
    suite.add(TestCase::new("sign_package", signature_tests::test_sign_package));
    suite.add(TestCase::new("compute_checksum", signature_tests::test_compute_checksum));
    suite.add(TestCase::new(
        "compute_checksum_deterministic",
        signature_tests::test_compute_checksum_deterministic,
    ));
    suite.add(TestCase::new(
        "compute_checksum_different_data",
        signature_tests::test_compute_checksum_different_data,
    ));
    suite.add(TestCase::new("verify_checksum_valid", signature_tests::test_verify_checksum_valid));
    suite.add(TestCase::new(
        "verify_checksum_invalid",
        signature_tests::test_verify_checksum_invalid,
    ));
    suite.add(TestCase::new(
        "verify_checksum_empty_data",
        signature_tests::test_verify_checksum_empty_data,
    ));
    suite.add(TestCase::new("list_trusted_keys", signature_tests::test_list_trusted_keys));
    suite.add(TestCase::new("add_trusted_key", signature_tests::test_add_trusted_key));
    suite.add(TestCase::new(
        "add_trusted_key_duplicate",
        signature_tests::test_add_trusted_key_duplicate,
    ));
    suite.add(TestCase::new("remove_trusted_key", signature_tests::test_remove_trusted_key));
    suite.add(TestCase::new(
        "get_trusted_key_not_found",
        signature_tests::test_get_trusted_key_not_found,
    ));

    // Types tests (32)
    suite.add(TestCase::new("architecture_current", types_tests::test_architecture_current));
    suite.add(TestCase::new(
        "architecture_from_str_x86_64",
        types_tests::test_architecture_from_str_x86_64,
    ));
    suite.add(TestCase::new(
        "architecture_from_str_amd64",
        types_tests::test_architecture_from_str_amd64,
    ));
    suite.add(TestCase::new(
        "architecture_from_str_aarch64",
        types_tests::test_architecture_from_str_aarch64,
    ));
    suite.add(TestCase::new(
        "architecture_from_str_arm64",
        types_tests::test_architecture_from_str_arm64,
    ));
    suite.add(TestCase::new(
        "architecture_from_str_any",
        types_tests::test_architecture_from_str_any,
    ));
    suite.add(TestCase::new(
        "architecture_from_str_noarch",
        types_tests::test_architecture_from_str_noarch,
    ));
    suite.add(TestCase::new(
        "architecture_from_str_invalid",
        types_tests::test_architecture_from_str_invalid,
    ));
    suite.add(TestCase::new("architecture_as_str", types_tests::test_architecture_as_str));
    suite.add(TestCase::new(
        "architecture_is_compatible_any",
        types_tests::test_architecture_is_compatible_any,
    ));
    suite.add(TestCase::new(
        "architecture_is_compatible_same",
        types_tests::test_architecture_is_compatible_same,
    ));
    suite.add(TestCase::new(
        "architecture_is_compatible_different",
        types_tests::test_architecture_is_compatible_different,
    ));
    suite.add(TestCase::new(
        "package_kind_from_str_binary",
        types_tests::test_package_kind_from_str_binary,
    ));
    suite.add(TestCase::new(
        "package_kind_from_str_library",
        types_tests::test_package_kind_from_str_library,
    ));
    suite.add(TestCase::new(
        "package_kind_from_str_data",
        types_tests::test_package_kind_from_str_data,
    ));
    suite.add(TestCase::new(
        "package_kind_from_str_font",
        types_tests::test_package_kind_from_str_font,
    ));
    suite.add(TestCase::new(
        "package_kind_from_str_theme",
        types_tests::test_package_kind_from_str_theme,
    ));
    suite.add(TestCase::new(
        "package_kind_from_str_driver",
        types_tests::test_package_kind_from_str_driver,
    ));
    suite.add(TestCase::new(
        "package_kind_from_str_service",
        types_tests::test_package_kind_from_str_service,
    ));
    suite.add(TestCase::new(
        "package_kind_from_str_meta",
        types_tests::test_package_kind_from_str_meta,
    ));
    suite.add(TestCase::new(
        "package_kind_from_str_invalid",
        types_tests::test_package_kind_from_str_invalid,
    ));
    suite.add(TestCase::new("package_kind_as_str", types_tests::test_package_kind_as_str));
    suite.add(TestCase::new("package_state_variants", types_tests::test_package_state_variants));
    suite.add(TestCase::new(
        "dependency_kind_from_str_runtime",
        types_tests::test_dependency_kind_from_str_runtime,
    ));
    suite.add(TestCase::new(
        "dependency_kind_from_str_build",
        types_tests::test_dependency_kind_from_str_build,
    ));
    suite.add(TestCase::new(
        "dependency_kind_from_str_optional",
        types_tests::test_dependency_kind_from_str_optional,
    ));
    suite.add(TestCase::new(
        "dependency_kind_from_str_conflict",
        types_tests::test_dependency_kind_from_str_conflict,
    ));
    suite.add(TestCase::new(
        "dependency_kind_from_str_replace",
        types_tests::test_dependency_kind_from_str_replace,
    ));
    suite.add(TestCase::new(
        "dependency_kind_from_str_provide",
        types_tests::test_dependency_kind_from_str_provide,
    ));
    suite.add(TestCase::new(
        "dependency_kind_from_str_invalid",
        types_tests::test_dependency_kind_from_str_invalid,
    ));
    suite
        .add(TestCase::new("file_permissions_default", types_tests::test_file_permissions_default));
    suite.add(TestCase::new(
        "file_permissions_executable",
        types_tests::test_file_permissions_executable,
    ));
    suite.add(TestCase::new(
        "file_permissions_directory",
        types_tests::test_file_permissions_directory,
    ));
    suite.add(TestCase::new("install_reason_variants", types_tests::test_install_reason_variants));
    suite.add(TestCase::new("package_id_new", types_tests::test_package_id_new));
    suite.add(TestCase::new("package_id_parse", types_tests::test_package_id_parse));
    suite.add(TestCase::new(
        "package_id_parse_with_hyphen_in_name",
        types_tests::test_package_id_parse_with_hyphen_in_name,
    ));
    suite
        .add(TestCase::new("package_id_parse_invalid", types_tests::test_package_id_parse_invalid));
    suite.add(TestCase::new("architecture_default", types_tests::test_architecture_default));
    suite.add(TestCase::new("package_kind_default", types_tests::test_package_kind_default));

    // Version tests (40)
    suite.add(TestCase::new("version_new", version_tests::test_version_new));
    suite.add(TestCase::new("version_parse_simple", version_tests::test_version_parse_simple));
    suite
        .add(TestCase::new("version_parse_two_parts", version_tests::test_version_parse_two_parts));
    suite.add(TestCase::new(
        "version_parse_with_prerelease",
        version_tests::test_version_parse_with_prerelease,
    ));
    suite.add(TestCase::new(
        "version_parse_with_build",
        version_tests::test_version_parse_with_build,
    ));
    suite.add(TestCase::new(
        "version_parse_with_prerelease_and_build",
        version_tests::test_version_parse_with_prerelease_and_build,
    ));
    suite.add(TestCase::new(
        "version_parse_with_whitespace",
        version_tests::test_version_parse_with_whitespace,
    ));
    suite.add(TestCase::new(
        "version_parse_invalid_single_part",
        version_tests::test_version_parse_invalid_single_part,
    ));
    suite.add(TestCase::new(
        "version_parse_invalid_four_parts",
        version_tests::test_version_parse_invalid_four_parts,
    ));
    suite.add(TestCase::new(
        "version_parse_invalid_non_numeric",
        version_tests::test_version_parse_invalid_non_numeric,
    ));
    suite.add(TestCase::new(
        "version_to_string_simple",
        version_tests::test_version_to_string_simple,
    ));
    suite.add(TestCase::new(
        "version_to_string_with_prerelease",
        version_tests::test_version_to_string_with_prerelease,
    ));
    suite.add(TestCase::new(
        "version_to_string_with_build",
        version_tests::test_version_to_string_with_build,
    ));
    suite.add(TestCase::new(
        "version_to_string_with_both",
        version_tests::test_version_to_string_with_both,
    ));
    suite.add(TestCase::new(
        "version_comparison_equal",
        version_tests::test_version_comparison_equal,
    ));
    suite.add(TestCase::new(
        "version_comparison_major",
        version_tests::test_version_comparison_major,
    ));
    suite.add(TestCase::new(
        "version_comparison_minor",
        version_tests::test_version_comparison_minor,
    ));
    suite.add(TestCase::new(
        "version_comparison_patch",
        version_tests::test_version_comparison_patch,
    ));
    suite.add(TestCase::new(
        "version_comparison_prerelease_less_than_release",
        version_tests::test_version_comparison_prerelease_less_than_release,
    ));
    suite.add(TestCase::new(
        "version_comparison_prerelease_ordering",
        version_tests::test_version_comparison_prerelease_ordering,
    ));
    suite.add(TestCase::new(
        "version_requirement_parse_any",
        version_tests::test_version_requirement_parse_any,
    ));
    suite.add(TestCase::new(
        "version_requirement_parse_empty",
        version_tests::test_version_requirement_parse_empty,
    ));
    suite.add(TestCase::new(
        "version_requirement_parse_exact",
        version_tests::test_version_requirement_parse_exact,
    ));
    suite.add(TestCase::new(
        "version_requirement_parse_exact_implicit",
        version_tests::test_version_requirement_parse_exact_implicit,
    ));
    suite.add(TestCase::new(
        "version_requirement_parse_greater_than",
        version_tests::test_version_requirement_parse_greater_than,
    ));
    suite.add(TestCase::new(
        "version_requirement_parse_greater_or_equal",
        version_tests::test_version_requirement_parse_greater_or_equal,
    ));
    suite.add(TestCase::new(
        "version_requirement_parse_less_than",
        version_tests::test_version_requirement_parse_less_than,
    ));
    suite.add(TestCase::new(
        "version_requirement_parse_less_or_equal",
        version_tests::test_version_requirement_parse_less_or_equal,
    ));
    suite.add(TestCase::new(
        "version_requirement_parse_compatible",
        version_tests::test_version_requirement_parse_compatible,
    ));
    suite.add(TestCase::new("version_satisfies_any", version_tests::test_version_satisfies_any));
    suite.add(TestCase::new(
        "version_satisfies_exact_true",
        version_tests::test_version_satisfies_exact_true,
    ));
    suite.add(TestCase::new(
        "version_satisfies_exact_false",
        version_tests::test_version_satisfies_exact_false,
    ));
    suite.add(TestCase::new(
        "version_satisfies_greater_than_true",
        version_tests::test_version_satisfies_greater_than_true,
    ));
    suite.add(TestCase::new(
        "version_satisfies_greater_than_false",
        version_tests::test_version_satisfies_greater_than_false,
    ));
    suite.add(TestCase::new(
        "version_satisfies_greater_or_equal_true",
        version_tests::test_version_satisfies_greater_or_equal_true,
    ));
    suite.add(TestCase::new(
        "version_satisfies_less_than_true",
        version_tests::test_version_satisfies_less_than_true,
    ));
    suite.add(TestCase::new(
        "version_satisfies_less_or_equal_true",
        version_tests::test_version_satisfies_less_or_equal_true,
    ));
    suite.add(TestCase::new(
        "version_satisfies_compatible_same_major",
        version_tests::test_version_satisfies_compatible_same_major,
    ));
    suite.add(TestCase::new(
        "version_satisfies_compatible_different_major",
        version_tests::test_version_satisfies_compatible_different_major,
    ));
    suite.add(TestCase::new(
        "version_satisfies_compatible_lower_version",
        version_tests::test_version_satisfies_compatible_lower_version,
    ));
    suite.add(TestCase::new("version_equality", version_tests::test_version_equality));
    suite.add(TestCase::new("version_clone", version_tests::test_version_clone));

    suite.run()
}
