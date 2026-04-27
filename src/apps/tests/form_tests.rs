// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

extern crate alloc;

use crate::apps::ecosystem::browser::form::{build_form_urlencoded, resolve_url, url_encode};
use crate::test::framework::TestResult;
use alloc::string::String;
use alloc::vec;

pub(crate) fn test_url_encode_unreserved() -> TestResult {
    if url_encode("hello") != "hello" {
        return TestResult::Fail;
    }
    if url_encode("ABC-_.~") != "ABC-_.~" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_url_encode_space() -> TestResult {
    if url_encode("hello world") != "hello+world" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_url_encode_special_chars() -> TestResult {
    if url_encode("a=b&c") != "a%3Db%26c" {
        return TestResult::Fail;
    }
    if url_encode("100%") != "100%25" {
        return TestResult::Fail;
    }
    if url_encode("@#$") != "%40%23%24" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_url_encode_unicode() -> TestResult {
    if url_encode("ñ") != "%C3%B1" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_url_encode_empty() -> TestResult {
    if url_encode("") != "" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_url_encode_numbers() -> TestResult {
    if url_encode("0123456789") != "0123456789" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_url_encode_mixed() -> TestResult {
    let encoded = url_encode("Hello World! @2026");
    if !encoded.contains("Hello") {
        return TestResult::Fail;
    }
    if !encoded.contains("+") {
        return TestResult::Fail;
    }
    if !encoded.contains("%40") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_build_form_urlencoded_empty() -> TestResult {
    let pairs: alloc::vec::Vec<(String, String)> = alloc::vec::Vec::new();
    if build_form_urlencoded(&pairs) != "" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_build_form_urlencoded_single() -> TestResult {
    let pairs = vec![(String::from("q"), String::from("rust lang"))];
    if build_form_urlencoded(&pairs) != "q=rust+lang" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_build_form_urlencoded_multiple() -> TestResult {
    let pairs = vec![
        (String::from("user"), String::from("admin")),
        (String::from("pass"), String::from("s3cr&t")),
    ];
    if build_form_urlencoded(&pairs) != "user=admin&pass=s3cr%26t" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_build_form_urlencoded_special_name() -> TestResult {
    let pairs = vec![(String::from("my field"), String::from("value"))];
    if build_form_urlencoded(&pairs) != "my+field=value" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_build_form_urlencoded_empty_value() -> TestResult {
    let pairs = vec![(String::from("key"), String::from(""))];
    if build_form_urlencoded(&pairs) != "key=" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolve_url_absolute() -> TestResult {
    let result = resolve_url("https://other.com/path", "https://example.com/");
    if result != "https://other.com/path" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolve_url_empty_action() -> TestResult {
    let result = resolve_url("", "https://example.com/page");
    if result != "https://example.com/page" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolve_url_absolute_path() -> TestResult {
    let result = resolve_url("/login", "https://example.com/some/page");
    if result != "https://example.com/login" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolve_url_relative_path() -> TestResult {
    let result = resolve_url("submit", "https://example.com/forms/edit");
    if result != "https://example.com/forms/submit" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolve_url_protocol_relative() -> TestResult {
    let result = resolve_url("//cdn.example.com/api", "https://example.com/");
    if result != "https://cdn.example.com/api" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolve_url_http_protocol_relative() -> TestResult {
    let result = resolve_url("//cdn.example.com/api", "http://example.com/");
    if result != "http://cdn.example.com/api" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolve_url_deep_relative() -> TestResult {
    let result = resolve_url("action.php", "https://example.com/dir/subdir/page.html");
    if result != "https://example.com/dir/subdir/action.php" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolve_url_root_relative() -> TestResult {
    let result = resolve_url("/api/submit", "https://example.com/deep/nested/path");
    if result != "https://example.com/api/submit" {
        return TestResult::Fail;
    }
    TestResult::Pass
}
