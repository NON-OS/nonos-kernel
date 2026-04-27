use crate::fs::path::*;
use crate::test::framework::TestResult;

pub(crate) fn test_path_constants_max_path_len() -> TestResult {
    if MAX_PATH_LEN != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_constants_max_component_len() -> TestResult {
    if MAX_COMPONENT_LEN != 255 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_constants_separator() -> TestResult {
    if PATH_SEPARATOR != '/' {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_constants_current_dir() -> TestResult {
    if CURRENT_DIR != "." {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_constants_parent_dir() -> TestResult {
    if PARENT_DIR != ".." {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_error_null_pointer_errno() -> TestResult {
    if PathError::NullPointer.to_errno() != -14 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_error_too_long_errno() -> TestResult {
    if PathError::TooLong.to_errno() != -36 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_error_invalid_utf8_errno() -> TestResult {
    if PathError::InvalidUtf8.to_errno() != -22 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_error_empty_errno() -> TestResult {
    if PathError::Empty.to_errno() != -22 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_error_contains_null_errno() -> TestResult {
    if PathError::ContainsNull.to_errno() != -22 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_error_component_too_long_errno() -> TestResult {
    if PathError::ComponentTooLong.to_errno() != -36 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_error_invalid_character_errno() -> TestResult {
    if PathError::InvalidCharacter.to_errno() != -22 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_error_traversal_attempt_errno() -> TestResult {
    if PathError::TraversalAttempt.to_errno() != -1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_error_not_absolute_errno() -> TestResult {
    if PathError::NotAbsolute.to_errno() != -22 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_error_not_relative_errno() -> TestResult {
    if PathError::NotRelative.to_errno() != -22 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_error_as_str_null_pointer() -> TestResult {
    if PathError::NullPointer.as_str() != "Null pointer" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_error_as_str_too_long() -> TestResult {
    if PathError::TooLong.as_str() != "Path too long" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_error_as_str_invalid_utf8() -> TestResult {
    if PathError::InvalidUtf8.as_str() != "Invalid UTF-8 in path" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_error_as_str_empty() -> TestResult {
    if PathError::Empty.as_str() != "Empty path" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_error_as_str_contains_null() -> TestResult {
    if PathError::ContainsNull.as_str() != "Path contains null byte" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_error_as_str_traversal() -> TestResult {
    if PathError::TraversalAttempt.as_str() != "Path traversal attempt" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_error_into_str() -> TestResult {
    let err = PathError::Empty;
    let s: &'static str = err.into();
    if s != "Empty path" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_path_empty() -> TestResult {
    if !validate_path("").is_err() {
        return TestResult::Fail;
    }
    if validate_path("").unwrap_err() != PathError::Empty {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_path_valid() -> TestResult {
    if !validate_path("/foo/bar").is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_path_null_byte() -> TestResult {
    if !validate_path("/foo\0bar").is_err() {
        return TestResult::Fail;
    }
    if validate_path("/foo\0bar").unwrap_err() != PathError::ContainsNull {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_path_too_long() -> TestResult {
    let long_path = "a".repeat(MAX_PATH_LEN + 1);
    if !validate_path(&long_path).is_err() {
        return TestResult::Fail;
    }
    if validate_path(&long_path).unwrap_err() != PathError::TooLong {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_path_secure_valid() -> TestResult {
    if !validate_path_secure("/foo/bar").is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_path_secure_traversal() -> TestResult {
    if !validate_path_secure("../etc/passwd").is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_path_secure_complex_traversal() -> TestResult {
    if !validate_path_secure("foo/../../etc").is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_absolute_root() -> TestResult {
    if !is_absolute("/") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_absolute_path() -> TestResult {
    if !is_absolute("/foo/bar") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_absolute_relative() -> TestResult {
    if is_absolute("foo/bar") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_absolute_empty() -> TestResult {
    if is_absolute("") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_relative_path() -> TestResult {
    if !is_relative("foo/bar") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_relative_absolute() -> TestResult {
    if is_relative("/foo/bar") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_relative_empty() -> TestResult {
    if is_relative("") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_normalize_path_simple() -> TestResult {
    if normalize_path("/foo/bar") != "/foo/bar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_normalize_path_double_slash() -> TestResult {
    if normalize_path("/foo//bar") != "/foo/bar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_normalize_path_dot() -> TestResult {
    if normalize_path("/foo/./bar") != "/foo/bar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_normalize_path_dotdot() -> TestResult {
    if normalize_path("/foo/bar/../baz") != "/foo/baz" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_normalize_path_dotdot_at_start() -> TestResult {
    if normalize_path("/foo/../bar") != "/bar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_normalize_path_multiple_dotdot() -> TestResult {
    if normalize_path("/foo/bar/../../baz") != "/baz" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_normalize_path_root() -> TestResult {
    if normalize_path("/") != "/" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_normalize_path_relative() -> TestResult {
    if normalize_path("foo/bar") != "foo/bar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_normalize_path_relative_with_dot() -> TestResult {
    if normalize_path("foo/./bar") != "foo/bar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_normalize_path_relative_with_dotdot() -> TestResult {
    if normalize_path("foo/bar/../baz") != "foo/baz" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_normalize_path_empty() -> TestResult {
    if normalize_path("") != "" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_normalize_path_only_dotdot() -> TestResult {
    if normalize_path("..") != ".." {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_normalize_path_relative_dotdot_start() -> TestResult {
    if normalize_path("../foo") != "../foo" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parent_simple() -> TestResult {
    if parent("/foo/bar") != "/foo" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parent_nested() -> TestResult {
    if parent("/foo/bar/baz") != "/foo/bar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parent_root_child() -> TestResult {
    if parent("/foo") != "/" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parent_root() -> TestResult {
    if parent("/") != "/" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parent_relative() -> TestResult {
    if parent("foo/bar") != "foo" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parent_relative_single() -> TestResult {
    if parent("foo") != "." {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parent_trailing_slash() -> TestResult {
    if parent("/foo/bar/") != "/foo" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parent_empty() -> TestResult {
    if parent("") != "" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_file_name_simple() -> TestResult {
    if file_name("/foo/bar.txt") != "bar.txt" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_file_name_no_extension() -> TestResult {
    if file_name("/foo/bar") != "bar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_file_name_trailing_slash() -> TestResult {
    if file_name("/foo/bar/") != "bar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_file_name_root() -> TestResult {
    if file_name("/") != "" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_file_name_relative() -> TestResult {
    if file_name("foo.txt") != "foo.txt" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_file_name_empty() -> TestResult {
    if file_name("") != "" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_extension_simple() -> TestResult {
    if extension("foo.txt") != Some("txt") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_extension_multiple_dots() -> TestResult {
    if extension("foo.tar.gz") != Some("gz") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_extension_none() -> TestResult {
    if extension("foo") != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_extension_hidden_file() -> TestResult {
    if extension(".hidden") != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_extension_hidden_with_ext() -> TestResult {
    if extension(".hidden.txt") != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_extension_path() -> TestResult {
    if extension("/foo/bar.txt") != Some("txt") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_extension_empty() -> TestResult {
    if extension("") != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_join_simple() -> TestResult {
    if join("/foo", "bar") != "/foo/bar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_join_trailing_slash() -> TestResult {
    if join("/foo/", "bar") != "/foo/bar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_join_absolute_child() -> TestResult {
    if join("/foo", "/bar") != "/bar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_join_empty_parent() -> TestResult {
    if join("", "bar") != "bar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_join_empty_child() -> TestResult {
    if join("/foo", "") != "/foo" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_join_normalize() -> TestResult {
    if join_normalize("/foo", "./bar") != "/foo/bar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_join_normalize_dotdot() -> TestResult {
    if join_normalize("/foo/bar", "../baz") != "/foo/baz" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_join_secure_valid() -> TestResult {
    let result = join_secure("/home/user", "documents/file.txt");
    if !result.is_ok() {
        return TestResult::Fail;
    }
    if result.unwrap() != "/home/user/documents/file.txt" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_join_secure_traversal() -> TestResult {
    let result = join_secure("/home/user", "../etc/passwd");
    if !result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_join_secure_absolute_child() -> TestResult {
    let result = join_secure("/home/user", "/etc/passwd");
    if !result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_components_absolute() -> TestResult {
    let path = "/foo/bar/baz";
    let parts: alloc::vec::Vec<&str> = components(path).collect();
    if parts != alloc::vec!["/", "foo", "bar", "baz"] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_components_relative() -> TestResult {
    let path = "foo/bar/baz";
    let parts: alloc::vec::Vec<&str> = components(path).collect();
    if parts != alloc::vec!["foo", "bar", "baz"] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_components_root() -> TestResult {
    let path = "/";
    let parts: alloc::vec::Vec<&str> = components(path).collect();
    if parts != alloc::vec!["/"] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_components_empty() -> TestResult {
    let path = "";
    let parts: alloc::vec::Vec<&str> = components(path).collect();
    if !parts.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_components_double_slash() -> TestResult {
    let path = "/foo//bar";
    let parts: alloc::vec::Vec<&str> = components(path).collect();
    if parts != alloc::vec!["/", "foo", "bar"] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_component_count_absolute() -> TestResult {
    if component_count("/foo/bar/baz") != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_component_count_relative() -> TestResult {
    if component_count("foo/bar") != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_component_count_empty() -> TestResult {
    if component_count("") != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_file_stem_simple() -> TestResult {
    if file_stem("foo.txt") != "foo" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_file_stem_multiple_dots() -> TestResult {
    if file_stem("foo.tar.gz") != "foo.tar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_file_stem_no_extension() -> TestResult {
    if file_stem("foo") != "foo" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_file_stem_hidden() -> TestResult {
    if file_stem(".hidden") != ".hidden" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_file_stem_path() -> TestResult {
    if file_stem("/foo/bar.txt") != "bar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_require_absolute_valid() -> TestResult {
    if !require_absolute("/foo/bar").is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_require_absolute_invalid() -> TestResult {
    if !require_absolute("foo/bar").is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_require_relative_valid() -> TestResult {
    if !require_relative("foo/bar").is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_require_relative_invalid() -> TestResult {
    if !require_relative("/foo/bar").is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_normalize_path_secure_valid() -> TestResult {
    let result = normalize_path_secure("/foo/bar", "/foo");
    if !result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_normalize_path_secure_traversal() -> TestResult {
    let result = normalize_path_secure("/etc/passwd", "/home");
    if !result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_error_equality() -> TestResult {
    if PathError::Empty != PathError::Empty {
        return TestResult::Fail;
    }
    if PathError::Empty == PathError::TooLong {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_path_error_copy() -> TestResult {
    let err1 = PathError::Empty;
    let err2 = err1;
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
