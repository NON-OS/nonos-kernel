use crate::fs::path::*;

#[test]
fn test_path_constants_max_path_len() {
    assert_eq!(MAX_PATH_LEN, 4096);
}

#[test]
fn test_path_constants_max_component_len() {
    assert_eq!(MAX_COMPONENT_LEN, 255);
}

#[test]
fn test_path_constants_separator() {
    assert_eq!(PATH_SEPARATOR, '/');
}

#[test]
fn test_path_constants_current_dir() {
    assert_eq!(CURRENT_DIR, ".");
}

#[test]
fn test_path_constants_parent_dir() {
    assert_eq!(PARENT_DIR, "..");
}

#[test]
fn test_path_error_null_pointer_errno() {
    assert_eq!(PathError::NullPointer.to_errno(), -14);
}

#[test]
fn test_path_error_too_long_errno() {
    assert_eq!(PathError::TooLong.to_errno(), -36);
}

#[test]
fn test_path_error_invalid_utf8_errno() {
    assert_eq!(PathError::InvalidUtf8.to_errno(), -22);
}

#[test]
fn test_path_error_empty_errno() {
    assert_eq!(PathError::Empty.to_errno(), -22);
}

#[test]
fn test_path_error_contains_null_errno() {
    assert_eq!(PathError::ContainsNull.to_errno(), -22);
}

#[test]
fn test_path_error_component_too_long_errno() {
    assert_eq!(PathError::ComponentTooLong.to_errno(), -36);
}

#[test]
fn test_path_error_invalid_character_errno() {
    assert_eq!(PathError::InvalidCharacter.to_errno(), -22);
}

#[test]
fn test_path_error_traversal_attempt_errno() {
    assert_eq!(PathError::TraversalAttempt.to_errno(), -1);
}

#[test]
fn test_path_error_not_absolute_errno() {
    assert_eq!(PathError::NotAbsolute.to_errno(), -22);
}

#[test]
fn test_path_error_not_relative_errno() {
    assert_eq!(PathError::NotRelative.to_errno(), -22);
}

#[test]
fn test_path_error_as_str_null_pointer() {
    assert_eq!(PathError::NullPointer.as_str(), "Null pointer");
}

#[test]
fn test_path_error_as_str_too_long() {
    assert_eq!(PathError::TooLong.as_str(), "Path too long");
}

#[test]
fn test_path_error_as_str_invalid_utf8() {
    assert_eq!(PathError::InvalidUtf8.as_str(), "Invalid UTF-8 in path");
}

#[test]
fn test_path_error_as_str_empty() {
    assert_eq!(PathError::Empty.as_str(), "Empty path");
}

#[test]
fn test_path_error_as_str_contains_null() {
    assert_eq!(PathError::ContainsNull.as_str(), "Path contains null byte");
}

#[test]
fn test_path_error_as_str_traversal() {
    assert_eq!(PathError::TraversalAttempt.as_str(), "Path traversal attempt");
}

#[test]
fn test_path_error_into_str() {
    let err = PathError::Empty;
    let s: &'static str = err.into();
    assert_eq!(s, "Empty path");
}

#[test]
fn test_validate_path_empty() {
    assert!(validate_path("").is_err());
    assert_eq!(validate_path("").unwrap_err(), PathError::Empty);
}

#[test]
fn test_validate_path_valid() {
    assert!(validate_path("/foo/bar").is_ok());
}

#[test]
fn test_validate_path_null_byte() {
    assert!(validate_path("/foo\0bar").is_err());
    assert_eq!(validate_path("/foo\0bar").unwrap_err(), PathError::ContainsNull);
}

#[test]
fn test_validate_path_too_long() {
    let long_path = "a".repeat(MAX_PATH_LEN + 1);
    assert!(validate_path(&long_path).is_err());
    assert_eq!(validate_path(&long_path).unwrap_err(), PathError::TooLong);
}

#[test]
fn test_validate_path_secure_valid() {
    assert!(validate_path_secure("/foo/bar").is_ok());
}

#[test]
fn test_validate_path_secure_traversal() {
    assert!(validate_path_secure("../etc/passwd").is_err());
}

#[test]
fn test_validate_path_secure_complex_traversal() {
    assert!(validate_path_secure("foo/../../etc").is_err());
}

#[test]
fn test_is_absolute_root() {
    assert!(is_absolute("/"));
}

#[test]
fn test_is_absolute_path() {
    assert!(is_absolute("/foo/bar"));
}

#[test]
fn test_is_absolute_relative() {
    assert!(!is_absolute("foo/bar"));
}

#[test]
fn test_is_absolute_empty() {
    assert!(!is_absolute(""));
}

#[test]
fn test_is_relative_path() {
    assert!(is_relative("foo/bar"));
}

#[test]
fn test_is_relative_absolute() {
    assert!(!is_relative("/foo/bar"));
}

#[test]
fn test_is_relative_empty() {
    assert!(!is_relative(""));
}

#[test]
fn test_normalize_path_simple() {
    assert_eq!(normalize_path("/foo/bar"), "/foo/bar");
}

#[test]
fn test_normalize_path_double_slash() {
    assert_eq!(normalize_path("/foo//bar"), "/foo/bar");
}

#[test]
fn test_normalize_path_dot() {
    assert_eq!(normalize_path("/foo/./bar"), "/foo/bar");
}

#[test]
fn test_normalize_path_dotdot() {
    assert_eq!(normalize_path("/foo/bar/../baz"), "/foo/baz");
}

#[test]
fn test_normalize_path_dotdot_at_start() {
    assert_eq!(normalize_path("/foo/../bar"), "/bar");
}

#[test]
fn test_normalize_path_multiple_dotdot() {
    assert_eq!(normalize_path("/foo/bar/../../baz"), "/baz");
}

#[test]
fn test_normalize_path_root() {
    assert_eq!(normalize_path("/"), "/");
}

#[test]
fn test_normalize_path_relative() {
    assert_eq!(normalize_path("foo/bar"), "foo/bar");
}

#[test]
fn test_normalize_path_relative_with_dot() {
    assert_eq!(normalize_path("foo/./bar"), "foo/bar");
}

#[test]
fn test_normalize_path_relative_with_dotdot() {
    assert_eq!(normalize_path("foo/bar/../baz"), "foo/baz");
}

#[test]
fn test_normalize_path_empty() {
    assert_eq!(normalize_path(""), "");
}

#[test]
fn test_normalize_path_only_dotdot() {
    assert_eq!(normalize_path(".."), "..");
}

#[test]
fn test_normalize_path_relative_dotdot_start() {
    assert_eq!(normalize_path("../foo"), "../foo");
}

#[test]
fn test_parent_simple() {
    assert_eq!(parent("/foo/bar"), "/foo");
}

#[test]
fn test_parent_nested() {
    assert_eq!(parent("/foo/bar/baz"), "/foo/bar");
}

#[test]
fn test_parent_root_child() {
    assert_eq!(parent("/foo"), "/");
}

#[test]
fn test_parent_root() {
    assert_eq!(parent("/"), "/");
}

#[test]
fn test_parent_relative() {
    assert_eq!(parent("foo/bar"), "foo");
}

#[test]
fn test_parent_relative_single() {
    assert_eq!(parent("foo"), ".");
}

#[test]
fn test_parent_trailing_slash() {
    assert_eq!(parent("/foo/bar/"), "/foo");
}

#[test]
fn test_parent_empty() {
    assert_eq!(parent(""), "");
}

#[test]
fn test_file_name_simple() {
    assert_eq!(file_name("/foo/bar.txt"), "bar.txt");
}

#[test]
fn test_file_name_no_extension() {
    assert_eq!(file_name("/foo/bar"), "bar");
}

#[test]
fn test_file_name_trailing_slash() {
    assert_eq!(file_name("/foo/bar/"), "bar");
}

#[test]
fn test_file_name_root() {
    assert_eq!(file_name("/"), "");
}

#[test]
fn test_file_name_relative() {
    assert_eq!(file_name("foo.txt"), "foo.txt");
}

#[test]
fn test_file_name_empty() {
    assert_eq!(file_name(""), "");
}

#[test]
fn test_extension_simple() {
    assert_eq!(extension("foo.txt"), Some("txt"));
}

#[test]
fn test_extension_multiple_dots() {
    assert_eq!(extension("foo.tar.gz"), Some("gz"));
}

#[test]
fn test_extension_none() {
    assert_eq!(extension("foo"), None);
}

#[test]
fn test_extension_hidden_file() {
    assert_eq!(extension(".hidden"), None);
}

#[test]
fn test_extension_hidden_with_ext() {
    assert_eq!(extension(".hidden.txt"), None);
}

#[test]
fn test_extension_path() {
    assert_eq!(extension("/foo/bar.txt"), Some("txt"));
}

#[test]
fn test_extension_empty() {
    assert_eq!(extension(""), None);
}

#[test]
fn test_join_simple() {
    assert_eq!(join("/foo", "bar"), "/foo/bar");
}

#[test]
fn test_join_trailing_slash() {
    assert_eq!(join("/foo/", "bar"), "/foo/bar");
}

#[test]
fn test_join_absolute_child() {
    assert_eq!(join("/foo", "/bar"), "/bar");
}

#[test]
fn test_join_empty_parent() {
    assert_eq!(join("", "bar"), "bar");
}

#[test]
fn test_join_empty_child() {
    assert_eq!(join("/foo", ""), "/foo");
}

#[test]
fn test_join_normalize() {
    assert_eq!(join_normalize("/foo", "./bar"), "/foo/bar");
}

#[test]
fn test_join_normalize_dotdot() {
    assert_eq!(join_normalize("/foo/bar", "../baz"), "/foo/baz");
}

#[test]
fn test_join_secure_valid() {
    let result = join_secure("/home/user", "documents/file.txt");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "/home/user/documents/file.txt");
}

#[test]
fn test_join_secure_traversal() {
    let result = join_secure("/home/user", "../etc/passwd");
    assert!(result.is_err());
}

#[test]
fn test_join_secure_absolute_child() {
    let result = join_secure("/home/user", "/etc/passwd");
    assert!(result.is_err());
}

#[test]
fn test_components_absolute() {
    let path = "/foo/bar/baz";
    let parts: alloc::vec::Vec<&str> = components(path).collect();
    assert_eq!(parts, alloc::vec!["/", "foo", "bar", "baz"]);
}

#[test]
fn test_components_relative() {
    let path = "foo/bar/baz";
    let parts: alloc::vec::Vec<&str> = components(path).collect();
    assert_eq!(parts, alloc::vec!["foo", "bar", "baz"]);
}

#[test]
fn test_components_root() {
    let path = "/";
    let parts: alloc::vec::Vec<&str> = components(path).collect();
    assert_eq!(parts, alloc::vec!["/"]);
}

#[test]
fn test_components_empty() {
    let path = "";
    let parts: alloc::vec::Vec<&str> = components(path).collect();
    assert!(parts.is_empty());
}

#[test]
fn test_components_double_slash() {
    let path = "/foo//bar";
    let parts: alloc::vec::Vec<&str> = components(path).collect();
    assert_eq!(parts, alloc::vec!["/", "foo", "bar"]);
}

#[test]
fn test_component_count_absolute() {
    assert_eq!(component_count("/foo/bar/baz"), 4);
}

#[test]
fn test_component_count_relative() {
    assert_eq!(component_count("foo/bar"), 2);
}

#[test]
fn test_component_count_empty() {
    assert_eq!(component_count(""), 0);
}

#[test]
fn test_file_stem_simple() {
    assert_eq!(file_stem("foo.txt"), "foo");
}

#[test]
fn test_file_stem_multiple_dots() {
    assert_eq!(file_stem("foo.tar.gz"), "foo.tar");
}

#[test]
fn test_file_stem_no_extension() {
    assert_eq!(file_stem("foo"), "foo");
}

#[test]
fn test_file_stem_hidden() {
    assert_eq!(file_stem(".hidden"), ".hidden");
}

#[test]
fn test_file_stem_path() {
    assert_eq!(file_stem("/foo/bar.txt"), "bar");
}

#[test]
fn test_require_absolute_valid() {
    assert!(require_absolute("/foo/bar").is_ok());
}

#[test]
fn test_require_absolute_invalid() {
    assert!(require_absolute("foo/bar").is_err());
}

#[test]
fn test_require_relative_valid() {
    assert!(require_relative("foo/bar").is_ok());
}

#[test]
fn test_require_relative_invalid() {
    assert!(require_relative("/foo/bar").is_err());
}

#[test]
fn test_normalize_path_secure_valid() {
    let result = normalize_path_secure("/foo/bar", "/foo");
    assert!(result.is_ok());
}

#[test]
fn test_normalize_path_secure_traversal() {
    let result = normalize_path_secure("/etc/passwd", "/home");
    assert!(result.is_err());
}

#[test]
fn test_path_error_equality() {
    assert_eq!(PathError::Empty, PathError::Empty);
    assert_ne!(PathError::Empty, PathError::TooLong);
}

#[test]
fn test_path_error_copy() {
    let err1 = PathError::Empty;
    let err2 = err1;
    assert_eq!(err1, err2);
}
