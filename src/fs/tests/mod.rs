pub mod cache_tests;
pub mod cryptofs_tests;
pub mod errors_tests;
pub mod fd_tests;
pub mod path_tests;
pub mod ramfs_tests;
pub mod storage_tests;
pub mod types_tests;
pub mod utils_tests;
pub mod vfs_tests;

use crate::test::framework::{TestCase, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("fs");

    // VFS tests (3 tests)
    suite.add(TestCase::new("vfs_module_exists", vfs_tests::test_module_exists));
    suite.add(TestCase::new("vfs_basic_constants", vfs_tests::test_basic_constants));
    suite.add(TestCase::new("vfs_basic_operations", vfs_tests::test_basic_operations));

    // RAMFS tests (47 tests)
    suite.add(TestCase::new(
        "fs_error_not_initialized_errno",
        ramfs_tests::test_fs_error_not_initialized_errno,
    ));
    suite
        .add(TestCase::new("fs_error_not_found_errno", ramfs_tests::test_fs_error_not_found_errno));
    suite.add(TestCase::new(
        "fs_error_already_exists_errno",
        ramfs_tests::test_fs_error_already_exists_errno,
    ));
    suite.add(TestCase::new(
        "fs_error_path_too_long_errno",
        ramfs_tests::test_fs_error_path_too_long_errno,
    ));
    suite.add(TestCase::new(
        "fs_error_invalid_path_errno",
        ramfs_tests::test_fs_error_invalid_path_errno,
    ));
    suite.add(TestCase::new(
        "fs_error_file_too_large_errno",
        ramfs_tests::test_fs_error_file_too_large_errno,
    ));
    suite.add(TestCase::new(
        "fs_error_too_many_files_errno",
        ramfs_tests::test_fs_error_too_many_files_errno,
    ));
    suite.add(TestCase::new(
        "fs_error_no_encryption_key_errno",
        ramfs_tests::test_fs_error_no_encryption_key_errno,
    ));
    suite.add(TestCase::new(
        "fs_error_data_too_short_errno",
        ramfs_tests::test_fs_error_data_too_short_errno,
    ));
    suite.add(TestCase::new(
        "fs_error_decryption_failed_errno",
        ramfs_tests::test_fs_error_decryption_failed_errno,
    ));
    suite.add(TestCase::new(
        "fs_error_encryption_failed_errno",
        ramfs_tests::test_fs_error_encryption_failed_errno,
    ));
    suite.add(TestCase::new(
        "fs_error_directory_not_found_errno",
        ramfs_tests::test_fs_error_directory_not_found_errno,
    ));
    suite.add(TestCase::new(
        "fs_error_not_a_directory_errno",
        ramfs_tests::test_fs_error_not_a_directory_errno,
    ));
    suite.add(TestCase::new(
        "fs_error_directory_not_empty_errno",
        ramfs_tests::test_fs_error_directory_not_empty_errno,
    ));
    suite.add(TestCase::new(
        "fs_error_permission_denied_errno",
        ramfs_tests::test_fs_error_permission_denied_errno,
    ));
    suite.add(TestCase::new(
        "fs_error_as_str_not_found",
        ramfs_tests::test_fs_error_as_str_not_found,
    ));
    suite.add(TestCase::new(
        "fs_error_as_str_already_exists",
        ramfs_tests::test_fs_error_as_str_already_exists,
    ));
    suite.add(TestCase::new(
        "fs_error_as_str_path_too_long",
        ramfs_tests::test_fs_error_as_str_path_too_long,
    ));
    suite.add(TestCase::new(
        "fs_error_as_str_invalid_path",
        ramfs_tests::test_fs_error_as_str_invalid_path,
    ));
    suite.add(TestCase::new(
        "fs_error_as_str_file_too_large",
        ramfs_tests::test_fs_error_as_str_file_too_large,
    ));
    suite.add(TestCase::new("fs_error_as_bytes", ramfs_tests::test_fs_error_as_bytes));
    suite.add(TestCase::new("fs_error_len", ramfs_tests::test_fs_error_len));
    suite.add(TestCase::new("fs_error_is_empty", ramfs_tests::test_fs_error_is_empty));
    suite.add(TestCase::new("fs_error_into_str", ramfs_tests::test_fs_error_into_str));
    suite.add(TestCase::new("fs_constants_nonce_size", ramfs_tests::test_fs_constants_nonce_size));
    suite.add(TestCase::new("fs_constants_tag_size", ramfs_tests::test_fs_constants_tag_size));
    suite.add(TestCase::new("fs_constants_key_size", ramfs_tests::test_fs_constants_key_size));
    suite.add(TestCase::new("fs_constants_salt_size", ramfs_tests::test_fs_constants_salt_size));
    suite.add(TestCase::new(
        "fs_constants_max_file_size",
        ramfs_tests::test_fs_constants_max_file_size,
    ));
    suite.add(TestCase::new(
        "fs_constants_max_path_len",
        ramfs_tests::test_fs_constants_max_path_len,
    ));
    suite.add(TestCase::new("fs_constants_max_files", ramfs_tests::test_fs_constants_max_files));
    suite.add(TestCase::new(
        "nonos_file_system_type_variants",
        ramfs_tests::test_nonos_file_system_type_variants,
    ));
    suite.add(TestCase::new("fs_statistics_default", ramfs_tests::test_fs_statistics_default));
    suite.add(TestCase::new("fs_statistics_clone", ramfs_tests::test_fs_statistics_clone));
    suite.add(TestCase::new("dir_entry_file", ramfs_tests::test_dir_entry_file));
    suite.add(TestCase::new("dir_entry_directory", ramfs_tests::test_dir_entry_directory));
    suite.add(TestCase::new("secure_zeroize", ramfs_tests::test_secure_zeroize));
    suite.add(TestCase::new("secure_zeroize_array", ramfs_tests::test_secure_zeroize_array));
    suite.add(TestCase::new("secure_zeroize_empty", ramfs_tests::test_secure_zeroize_empty));
    suite.add(TestCase::new(
        "secure_zeroize_single_byte",
        ramfs_tests::test_secure_zeroize_single_byte,
    ));
    suite.add(TestCase::new("normalize_path_absolute", ramfs_tests::test_normalize_path_absolute));
    suite.add(TestCase::new(
        "normalize_path_double_slash",
        ramfs_tests::test_normalize_path_double_slash,
    ));
    suite.add(TestCase::new("normalize_path_dot", ramfs_tests::test_normalize_path_dot));
    suite.add(TestCase::new("normalize_path_dotdot", ramfs_tests::test_normalize_path_dotdot));
    suite.add(TestCase::new("normalize_path_relative", ramfs_tests::test_normalize_path_relative));
    suite.add(TestCase::new(
        "normalize_path_empty_result",
        ramfs_tests::test_normalize_path_empty_result,
    ));
    suite.add(TestCase::new("nonos_file_info_clone", ramfs_tests::test_nonos_file_info_clone));
    suite.add(TestCase::new("nonos_file_clone", ramfs_tests::test_nonos_file_clone));
    suite.add(TestCase::new("dir_entry_clone", ramfs_tests::test_dir_entry_clone));
    suite.add(TestCase::new(
        "fs_statistics_with_values",
        ramfs_tests::test_fs_statistics_with_values,
    ));
    suite.add(TestCase::new(
        "nonos_file_system_type_equality",
        ramfs_tests::test_nonos_file_system_type_equality,
    ));
    suite.add(TestCase::new("fs_error_io_error", ramfs_tests::test_fs_error_io_error));

    // CryptoFS tests (3 tests)
    suite.add(TestCase::new("cryptofs_module_exists", cryptofs_tests::test_module_exists));
    suite.add(TestCase::new("cryptofs_basic_constants", cryptofs_tests::test_basic_constants));
    suite.add(TestCase::new("cryptofs_basic_operations", cryptofs_tests::test_basic_operations));

    // Cache tests (49 tests)
    suite.add(TestCase::new("cache_stats_default", cache_tests::test_cache_stats_default));
    suite.add(TestCase::new(
        "cache_stats_hit_ratio_zero",
        cache_tests::test_cache_stats_hit_ratio_zero,
    ));
    suite.add(TestCase::new(
        "cache_stats_hit_ratio_all_hits",
        cache_tests::test_cache_stats_hit_ratio_all_hits,
    ));
    suite.add(TestCase::new(
        "cache_stats_hit_ratio_all_misses",
        cache_tests::test_cache_stats_hit_ratio_all_misses,
    ));
    suite.add(TestCase::new(
        "cache_stats_hit_ratio_mixed",
        cache_tests::test_cache_stats_hit_ratio_mixed,
    ));
    suite.add(TestCase::new("cache_stats_clone", cache_tests::test_cache_stats_clone));
    suite.add(TestCase::new("cache_statistics_new", cache_tests::test_cache_statistics_new));
    suite.add(TestCase::new(
        "cache_statistics_hit_ratio_zero",
        cache_tests::test_cache_statistics_hit_ratio_zero,
    ));
    suite.add(TestCase::new("cache_statistics_reset", cache_tests::test_cache_statistics_reset));
    suite.add(TestCase::new(
        "cache_constants_max_cached_pages",
        cache_tests::test_cache_constants_max_cached_pages,
    ));
    suite.add(TestCase::new(
        "cache_constants_writeback_batch_size",
        cache_tests::test_cache_constants_writeback_batch_size,
    ));
    suite.add(TestCase::new(
        "cache_constants_max_cached_inodes",
        cache_tests::test_cache_constants_max_cached_inodes,
    ));
    suite.add(TestCase::new(
        "cache_constants_max_operation_retries",
        cache_tests::test_cache_constants_max_operation_retries,
    ));
    suite.add(TestCase::new("directory_entry_file", cache_tests::test_directory_entry_file));
    suite.add(TestCase::new("directory_entry_clone", cache_tests::test_directory_entry_clone));
    suite.add(TestCase::new("cached_inode_basic", cache_tests::test_cached_inode_basic));
    suite.add(TestCase::new("cached_inode_dirty", cache_tests::test_cached_inode_dirty));
    suite.add(TestCase::new("cached_inode_clone", cache_tests::test_cached_inode_clone));
    suite.add(TestCase::new("dirty_page_basic", cache_tests::test_dirty_page_basic));
    suite.add(TestCase::new("file_info_basic", cache_tests::test_file_info_basic));
    suite.add(TestCase::new("file_info_clone", cache_tests::test_file_info_clone));
    suite.add(TestCase::new("get_cache_statistics", cache_tests::test_get_cache_statistics));
    suite.add(TestCase::new("get_cache_hit_ratio", cache_tests::test_get_cache_hit_ratio));
    suite.add(TestCase::new("init_all_caches", cache_tests::test_init_all_caches));
    suite.add(TestCase::new("clear_all_caches", cache_tests::test_clear_all_caches));
    suite.add(TestCase::new("init_page_cache", cache_tests::test_init_page_cache));
    suite.add(TestCase::new("clear_page_cache", cache_tests::test_clear_page_cache));
    suite.add(TestCase::new("get_page_cache_stats", cache_tests::test_get_page_cache_stats));
    suite.add(TestCase::new("init_dentry_cache", cache_tests::test_init_dentry_cache));
    suite.add(TestCase::new("clear_dentry_cache", cache_tests::test_clear_dentry_cache));
    suite.add(TestCase::new("init_inode_cache", cache_tests::test_init_inode_cache));
    suite.add(TestCase::new("clear_inode_cache", cache_tests::test_clear_inode_cache));
    suite.add(TestCase::new("cleanup_unused_inodes", cache_tests::test_cleanup_unused_inodes));
    suite.add(TestCase::new("update_inode_timestamps", cache_tests::test_update_inode_timestamps));
    suite.add(TestCase::new("writeback_dirty_inodes", cache_tests::test_writeback_dirty_inodes));
    suite.add(TestCase::new(
        "get_full_cache_statistics",
        cache_tests::test_get_full_cache_statistics,
    ));
    suite.add(TestCase::new("lookup_dentry_not_found", cache_tests::test_lookup_dentry_not_found));
    suite.add(TestCase::new("update_directory_entry", cache_tests::test_update_directory_entry));
    suite.add(TestCase::new(
        "lookup_dentry_after_insert",
        cache_tests::test_lookup_dentry_after_insert,
    ));
    suite.add(TestCase::new("remove_dentry", cache_tests::test_remove_dentry));
    suite.add(TestCase::new("queue_dentry_update", cache_tests::test_queue_dentry_update));
    suite.add(TestCase::new(
        "get_pending_dentry_updates",
        cache_tests::test_get_pending_dentry_updates,
    ));
    suite.add(TestCase::new(
        "process_inode_cache_maintenance",
        cache_tests::test_process_inode_cache_maintenance,
    ));
    suite.add(TestCase::new("cache_page", cache_tests::test_cache_page));
    suite.add(TestCase::new("get_cached_page", cache_tests::test_get_cached_page));
    suite.add(TestCase::new(
        "get_cached_page_not_found",
        cache_tests::test_get_cached_page_not_found,
    ));
    suite.add(TestCase::new("mark_page_clean", cache_tests::test_mark_page_clean));
    suite.add(TestCase::new("cache_inode", cache_tests::test_cache_inode));
    suite.add(TestCase::new("get_cached_inode", cache_tests::test_get_cached_inode));
    suite.add(TestCase::new(
        "get_cached_inode_not_found",
        cache_tests::test_get_cached_inode_not_found,
    ));

    // Path tests (88 tests)
    suite.add(TestCase::new(
        "path_constants_max_path_len",
        path_tests::test_path_constants_max_path_len,
    ));
    suite.add(TestCase::new(
        "path_constants_max_component_len",
        path_tests::test_path_constants_max_component_len,
    ));
    suite.add(TestCase::new("path_constants_separator", path_tests::test_path_constants_separator));
    suite.add(TestCase::new(
        "path_constants_current_dir",
        path_tests::test_path_constants_current_dir,
    ));
    suite.add(TestCase::new(
        "path_constants_parent_dir",
        path_tests::test_path_constants_parent_dir,
    ));
    suite.add(TestCase::new(
        "path_error_null_pointer_errno",
        path_tests::test_path_error_null_pointer_errno,
    ));
    suite.add(TestCase::new(
        "path_error_too_long_errno",
        path_tests::test_path_error_too_long_errno,
    ));
    suite.add(TestCase::new(
        "path_error_invalid_utf8_errno",
        path_tests::test_path_error_invalid_utf8_errno,
    ));
    suite.add(TestCase::new("path_error_empty_errno", path_tests::test_path_error_empty_errno));
    suite.add(TestCase::new(
        "path_error_contains_null_errno",
        path_tests::test_path_error_contains_null_errno,
    ));
    suite.add(TestCase::new(
        "path_error_component_too_long_errno",
        path_tests::test_path_error_component_too_long_errno,
    ));
    suite.add(TestCase::new(
        "path_error_invalid_character_errno",
        path_tests::test_path_error_invalid_character_errno,
    ));
    suite.add(TestCase::new(
        "path_error_traversal_attempt_errno",
        path_tests::test_path_error_traversal_attempt_errno,
    ));
    suite.add(TestCase::new(
        "path_error_not_absolute_errno",
        path_tests::test_path_error_not_absolute_errno,
    ));
    suite.add(TestCase::new(
        "path_error_not_relative_errno",
        path_tests::test_path_error_not_relative_errno,
    ));
    suite.add(TestCase::new(
        "path_error_as_str_null_pointer",
        path_tests::test_path_error_as_str_null_pointer,
    ));
    suite.add(TestCase::new(
        "path_error_as_str_too_long",
        path_tests::test_path_error_as_str_too_long,
    ));
    suite.add(TestCase::new(
        "path_error_as_str_invalid_utf8",
        path_tests::test_path_error_as_str_invalid_utf8,
    ));
    suite.add(TestCase::new("path_error_as_str_empty", path_tests::test_path_error_as_str_empty));
    suite.add(TestCase::new(
        "path_error_as_str_contains_null",
        path_tests::test_path_error_as_str_contains_null,
    ));
    suite.add(TestCase::new(
        "path_error_as_str_traversal",
        path_tests::test_path_error_as_str_traversal,
    ));
    suite.add(TestCase::new("path_error_into_str", path_tests::test_path_error_into_str));
    suite.add(TestCase::new("validate_path_empty", path_tests::test_validate_path_empty));
    suite.add(TestCase::new("validate_path_valid", path_tests::test_validate_path_valid));
    suite.add(TestCase::new("validate_path_null_byte", path_tests::test_validate_path_null_byte));
    suite.add(TestCase::new("validate_path_too_long", path_tests::test_validate_path_too_long));
    suite.add(TestCase::new(
        "validate_path_secure_valid",
        path_tests::test_validate_path_secure_valid,
    ));
    suite.add(TestCase::new(
        "validate_path_secure_traversal",
        path_tests::test_validate_path_secure_traversal,
    ));
    suite.add(TestCase::new(
        "validate_path_secure_complex_traversal",
        path_tests::test_validate_path_secure_complex_traversal,
    ));
    suite.add(TestCase::new("is_absolute_root", path_tests::test_is_absolute_root));
    suite.add(TestCase::new("is_absolute_path", path_tests::test_is_absolute_path));
    suite.add(TestCase::new("is_absolute_relative", path_tests::test_is_absolute_relative));
    suite.add(TestCase::new("is_absolute_empty", path_tests::test_is_absolute_empty));
    suite.add(TestCase::new("is_relative_path", path_tests::test_is_relative_path));
    suite.add(TestCase::new("is_relative_absolute", path_tests::test_is_relative_absolute));
    suite.add(TestCase::new("is_relative_empty", path_tests::test_is_relative_empty));
    suite.add(TestCase::new("normalize_path_simple", path_tests::test_normalize_path_simple));
    suite.add(TestCase::new(
        "path_normalize_path_double_slash",
        path_tests::test_normalize_path_double_slash,
    ));
    suite.add(TestCase::new("path_normalize_path_dot", path_tests::test_normalize_path_dot));
    suite.add(TestCase::new("path_normalize_path_dotdot", path_tests::test_normalize_path_dotdot));
    suite.add(TestCase::new(
        "normalize_path_dotdot_at_start",
        path_tests::test_normalize_path_dotdot_at_start,
    ));
    suite.add(TestCase::new(
        "normalize_path_multiple_dotdot",
        path_tests::test_normalize_path_multiple_dotdot,
    ));
    suite.add(TestCase::new("normalize_path_root", path_tests::test_normalize_path_root));
    suite.add(TestCase::new(
        "path_normalize_path_relative",
        path_tests::test_normalize_path_relative,
    ));
    suite.add(TestCase::new(
        "normalize_path_relative_with_dot",
        path_tests::test_normalize_path_relative_with_dot,
    ));
    suite.add(TestCase::new(
        "normalize_path_relative_with_dotdot",
        path_tests::test_normalize_path_relative_with_dotdot,
    ));
    suite.add(TestCase::new("normalize_path_empty", path_tests::test_normalize_path_empty));
    suite.add(TestCase::new(
        "normalize_path_only_dotdot",
        path_tests::test_normalize_path_only_dotdot,
    ));
    suite.add(TestCase::new(
        "normalize_path_relative_dotdot_start",
        path_tests::test_normalize_path_relative_dotdot_start,
    ));
    suite.add(TestCase::new("parent_simple", path_tests::test_parent_simple));
    suite.add(TestCase::new("parent_nested", path_tests::test_parent_nested));
    suite.add(TestCase::new("parent_root_child", path_tests::test_parent_root_child));
    suite.add(TestCase::new("parent_root", path_tests::test_parent_root));
    suite.add(TestCase::new("parent_relative", path_tests::test_parent_relative));
    suite.add(TestCase::new("parent_relative_single", path_tests::test_parent_relative_single));
    suite.add(TestCase::new("parent_trailing_slash", path_tests::test_parent_trailing_slash));
    suite.add(TestCase::new("parent_empty", path_tests::test_parent_empty));
    suite.add(TestCase::new("file_name_simple", path_tests::test_file_name_simple));
    suite.add(TestCase::new("file_name_no_extension", path_tests::test_file_name_no_extension));
    suite.add(TestCase::new("file_name_trailing_slash", path_tests::test_file_name_trailing_slash));
    suite.add(TestCase::new("file_name_root", path_tests::test_file_name_root));
    suite.add(TestCase::new("file_name_relative", path_tests::test_file_name_relative));
    suite.add(TestCase::new("file_name_empty", path_tests::test_file_name_empty));
    suite.add(TestCase::new("extension_simple", path_tests::test_extension_simple));
    suite.add(TestCase::new("extension_multiple_dots", path_tests::test_extension_multiple_dots));
    suite.add(TestCase::new("extension_none", path_tests::test_extension_none));
    suite.add(TestCase::new("extension_hidden_file", path_tests::test_extension_hidden_file));
    suite.add(TestCase::new(
        "extension_hidden_with_ext",
        path_tests::test_extension_hidden_with_ext,
    ));
    suite.add(TestCase::new("extension_path", path_tests::test_extension_path));
    suite.add(TestCase::new("extension_empty", path_tests::test_extension_empty));
    suite.add(TestCase::new("join_simple", path_tests::test_join_simple));
    suite.add(TestCase::new("join_trailing_slash", path_tests::test_join_trailing_slash));
    suite.add(TestCase::new("join_absolute_child", path_tests::test_join_absolute_child));
    suite.add(TestCase::new("join_empty_parent", path_tests::test_join_empty_parent));
    suite.add(TestCase::new("join_empty_child", path_tests::test_join_empty_child));
    suite.add(TestCase::new("join_normalize", path_tests::test_join_normalize));
    suite.add(TestCase::new("join_normalize_dotdot", path_tests::test_join_normalize_dotdot));
    suite.add(TestCase::new("join_secure_valid", path_tests::test_join_secure_valid));
    suite.add(TestCase::new("join_secure_traversal", path_tests::test_join_secure_traversal));
    suite.add(TestCase::new(
        "join_secure_absolute_child",
        path_tests::test_join_secure_absolute_child,
    ));
    suite.add(TestCase::new("components_absolute", path_tests::test_components_absolute));
    suite.add(TestCase::new("components_relative", path_tests::test_components_relative));
    suite.add(TestCase::new("components_root", path_tests::test_components_root));
    suite.add(TestCase::new("components_empty", path_tests::test_components_empty));
    suite.add(TestCase::new("components_double_slash", path_tests::test_components_double_slash));
    suite.add(TestCase::new("component_count_absolute", path_tests::test_component_count_absolute));
    suite.add(TestCase::new("component_count_relative", path_tests::test_component_count_relative));
    suite.add(TestCase::new("component_count_empty", path_tests::test_component_count_empty));
    suite.add(TestCase::new("file_stem_simple", path_tests::test_file_stem_simple));
    suite.add(TestCase::new("file_stem_multiple_dots", path_tests::test_file_stem_multiple_dots));
    suite.add(TestCase::new("file_stem_no_extension", path_tests::test_file_stem_no_extension));
    suite.add(TestCase::new("file_stem_hidden", path_tests::test_file_stem_hidden));
    suite.add(TestCase::new("file_stem_path", path_tests::test_file_stem_path));
    suite.add(TestCase::new("require_absolute_valid", path_tests::test_require_absolute_valid));
    suite.add(TestCase::new("require_absolute_invalid", path_tests::test_require_absolute_invalid));
    suite.add(TestCase::new("require_relative_valid", path_tests::test_require_relative_valid));
    suite.add(TestCase::new("require_relative_invalid", path_tests::test_require_relative_invalid));
    suite.add(TestCase::new(
        "normalize_path_secure_valid",
        path_tests::test_normalize_path_secure_valid,
    ));
    suite.add(TestCase::new(
        "normalize_path_secure_traversal",
        path_tests::test_normalize_path_secure_traversal,
    ));
    suite.add(TestCase::new("path_error_equality", path_tests::test_path_error_equality));
    suite.add(TestCase::new("path_error_copy", path_tests::test_path_error_copy));

    // FD tests (3 tests)
    suite.add(TestCase::new("fd_module_exists", fd_tests::test_module_exists));
    suite.add(TestCase::new("fd_basic_constants", fd_tests::test_basic_constants));
    suite.add(TestCase::new("fd_basic_operations", fd_tests::test_basic_operations));

    // Storage tests (55 tests)
    suite.add(TestCase::new(
        "storage_constants_default_max_storage",
        storage_tests::test_storage_constants_default_max_storage,
    ));
    suite.add(TestCase::new(
        "storage_constants_default_max_files",
        storage_tests::test_storage_constants_default_max_files,
    ));
    suite.add(TestCase::new(
        "storage_constants_block_size",
        storage_tests::test_storage_constants_block_size,
    ));
    suite.add(TestCase::new(
        "storage_constants_inode_size",
        storage_tests::test_storage_constants_inode_size,
    ));
    suite.add(TestCase::new(
        "storage_constants_warning_threshold",
        storage_tests::test_storage_constants_warning_threshold,
    ));
    suite.add(TestCase::new(
        "storage_constants_critical_threshold",
        storage_tests::test_storage_constants_critical_threshold,
    ));
    suite.add(TestCase::new(
        "storage_health_status_variants",
        storage_tests::test_storage_health_status_variants,
    ));
    suite.add(TestCase::new("storage_stats_default", storage_tests::test_storage_stats_default));
    suite.add(TestCase::new(
        "storage_stats_usage_percent_zero",
        storage_tests::test_storage_stats_usage_percent_zero,
    ));
    suite.add(TestCase::new(
        "storage_stats_usage_percent_half",
        storage_tests::test_storage_stats_usage_percent_half,
    ));
    suite.add(TestCase::new(
        "storage_stats_usage_percent_full",
        storage_tests::test_storage_stats_usage_percent_full,
    ));
    suite.add(TestCase::new(
        "storage_stats_free_percent",
        storage_tests::test_storage_stats_free_percent,
    ));
    suite.add(TestCase::new(
        "storage_stats_block_usage_percent",
        storage_tests::test_storage_stats_block_usage_percent,
    ));
    suite.add(TestCase::new(
        "storage_stats_block_usage_percent_zero_total",
        storage_tests::test_storage_stats_block_usage_percent_zero_total,
    ));
    suite.add(TestCase::new("storage_stats_clone", storage_tests::test_storage_stats_clone));
    suite.add(TestCase::new(
        "filesystem_breakdown_default",
        storage_tests::test_filesystem_breakdown_default,
    ));
    suite.add(TestCase::new(
        "filesystem_breakdown_total_bytes",
        storage_tests::test_filesystem_breakdown_total_bytes,
    ));
    suite.add(TestCase::new(
        "filesystem_breakdown_total_files",
        storage_tests::test_filesystem_breakdown_total_files,
    ));
    suite.add(TestCase::new(
        "filesystem_breakdown_clone",
        storage_tests::test_filesystem_breakdown_clone,
    ));
    suite.add(TestCase::new("storage_health_default", storage_tests::test_storage_health_default));
    suite.add(TestCase::new("storage_health_clone", storage_tests::test_storage_health_clone));
    suite.add(TestCase::new("storage_issues_default", storage_tests::test_storage_issues_default));
    suite.add(TestCase::new(
        "storage_issues_has_issues_none",
        storage_tests::test_storage_issues_has_issues_none,
    ));
    suite.add(TestCase::new(
        "storage_issues_has_issues_low_space",
        storage_tests::test_storage_issues_has_issues_low_space,
    ));
    suite.add(TestCase::new(
        "storage_issues_has_issues_low_inodes",
        storage_tests::test_storage_issues_has_issues_low_inodes,
    ));
    suite.add(TestCase::new(
        "storage_issues_has_issues_high_fragmentation",
        storage_tests::test_storage_issues_has_issues_high_fragmentation,
    ));
    suite.add(TestCase::new(
        "storage_issues_has_issues_allocation_failures",
        storage_tests::test_storage_issues_has_issues_allocation_failures,
    ));
    suite.add(TestCase::new(
        "storage_issues_has_issues_io_errors",
        storage_tests::test_storage_issues_has_issues_io_errors,
    ));
    suite.add(TestCase::new(
        "storage_issues_issue_count_zero",
        storage_tests::test_storage_issues_issue_count_zero,
    ));
    suite.add(TestCase::new(
        "storage_issues_issue_count_all",
        storage_tests::test_storage_issues_issue_count_all,
    ));
    suite.add(TestCase::new(
        "storage_issues_issue_count_some",
        storage_tests::test_storage_issues_issue_count_some,
    ));
    suite.add(TestCase::new("storage_issues_clone", storage_tests::test_storage_issues_clone));
    suite.add(TestCase::new("inode_stats_default", storage_tests::test_inode_stats_default));
    suite.add(TestCase::new(
        "inode_stats_usage_percent_zero",
        storage_tests::test_inode_stats_usage_percent_zero,
    ));
    suite.add(TestCase::new(
        "inode_stats_usage_percent_half",
        storage_tests::test_inode_stats_usage_percent_half,
    ));
    suite.add(TestCase::new(
        "inode_stats_usage_percent_zero_total",
        storage_tests::test_inode_stats_usage_percent_zero_total,
    ));
    suite.add(TestCase::new("inode_stats_clone", storage_tests::test_inode_stats_clone));
    suite.add(TestCase::new("storage_quota_default", storage_tests::test_storage_quota_default));
    suite.add(TestCase::new(
        "storage_quota_is_soft_exceeded_false",
        storage_tests::test_storage_quota_is_soft_exceeded_false,
    ));
    suite.add(TestCase::new(
        "storage_quota_is_soft_exceeded_true",
        storage_tests::test_storage_quota_is_soft_exceeded_true,
    ));
    suite.add(TestCase::new(
        "storage_quota_is_hard_exceeded_false",
        storage_tests::test_storage_quota_is_hard_exceeded_false,
    ));
    suite.add(TestCase::new(
        "storage_quota_is_hard_exceeded_true",
        storage_tests::test_storage_quota_is_hard_exceeded_true,
    ));
    suite.add(TestCase::new(
        "storage_quota_remaining_bytes",
        storage_tests::test_storage_quota_remaining_bytes,
    ));
    suite.add(TestCase::new(
        "storage_quota_remaining_bytes_none",
        storage_tests::test_storage_quota_remaining_bytes_none,
    ));
    suite.add(TestCase::new(
        "storage_quota_remaining_files",
        storage_tests::test_storage_quota_remaining_files,
    ));
    suite.add(TestCase::new("storage_quota_clone", storage_tests::test_storage_quota_clone));
    suite.add(TestCase::new("get_storage_stats", storage_tests::test_get_storage_stats));
    suite.add(TestCase::new("get_total_used_bytes", storage_tests::test_get_total_used_bytes));
    suite.add(TestCase::new(
        "get_total_available_bytes",
        storage_tests::test_get_total_available_bytes,
    ));
    suite.add(TestCase::new(
        "get_storage_usage_percent",
        storage_tests::test_get_storage_usage_percent,
    ));
    suite.add(TestCase::new(
        "get_filesystem_breakdown",
        storage_tests::test_get_filesystem_breakdown,
    ));
    suite.add(TestCase::new("get_storage_health", storage_tests::test_get_storage_health));
    suite.add(TestCase::new("get_inode_stats", storage_tests::test_get_inode_stats));
    suite.add(TestCase::new("get_quota", storage_tests::test_get_quota));
    suite.add(TestCase::new("get_remaining_capacity", storage_tests::test_get_remaining_capacity));
    suite.add(TestCase::new("is_soft_limit_exceeded", storage_tests::test_is_soft_limit_exceeded));
    suite.add(TestCase::new("is_hard_limit_exceeded", storage_tests::test_is_hard_limit_exceeded));
    suite.add(TestCase::new("check_can_allocate", storage_tests::test_check_can_allocate));
    suite.add(TestCase::new("check_can_create_file", storage_tests::test_check_can_create_file));

    // Types tests (3 tests)
    suite.add(TestCase::new("types_module_exists", types_tests::test_module_exists));
    suite.add(TestCase::new("types_basic_constants", types_tests::test_basic_constants));
    suite.add(TestCase::new("types_basic_operations", types_tests::test_basic_operations));

    // Utils tests (3 tests)
    suite.add(TestCase::new("utils_module_exists", utils_tests::test_module_exists));
    suite.add(TestCase::new("utils_basic_constants", utils_tests::test_basic_constants));
    suite.add(TestCase::new("utils_basic_operations", utils_tests::test_basic_operations));

    // Errors tests (3 tests)
    suite.add(TestCase::new("errors_module_exists", errors_tests::test_module_exists));
    suite.add(TestCase::new("errors_basic_constants", errors_tests::test_basic_constants));
    suite.add(TestCase::new("errors_basic_operations", errors_tests::test_basic_operations));

    suite.run()
}
