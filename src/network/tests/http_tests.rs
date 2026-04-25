// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::network::http_client::request::{HttpMethod, HttpRequestOptions};
use crate::network::http_client::response::HttpResponse;
use crate::test::framework::TestResult;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

pub(crate) fn test_http_method_get() -> TestResult {
    let method = HttpMethod::Get;
    if method != HttpMethod::Get {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_method_head() -> TestResult {
    let method = HttpMethod::Head;
    if method != HttpMethod::Head {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_method_post() -> TestResult {
    let method = HttpMethod::Post;
    if method != HttpMethod::Post {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_method_put() -> TestResult {
    let method = HttpMethod::Put;
    if method != HttpMethod::Put {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_method_delete() -> TestResult {
    let method = HttpMethod::Delete;
    if method != HttpMethod::Delete {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_method_clone() -> TestResult {
    let method = HttpMethod::Get;
    let cloned = method.clone();
    if method != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_method_copy() -> TestResult {
    let method1 = HttpMethod::Post;
    let method2 = method1;
    if method1 != method2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_method_equality() -> TestResult {
    if HttpMethod::Get != HttpMethod::Get {
        return TestResult::Fail;
    }
    if HttpMethod::Get == HttpMethod::Post {
        return TestResult::Fail;
    }
    if HttpMethod::Put == HttpMethod::Delete {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_method_debug() -> TestResult {
    let method = HttpMethod::Delete;
    let debug_str = alloc::format!("{:?}", method);
    if !debug_str.contains("Delete") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_request_options_default() -> TestResult {
    let options = HttpRequestOptions::default();
    if options.method != HttpMethod::Get {
        return TestResult::Fail;
    }
    if !options.headers.is_empty() {
        return TestResult::Fail;
    }
    if !options.body.is_none() {
        return TestResult::Fail;
    }
    if !options.follow_redirects {
        return TestResult::Fail;
    }
    if options.max_redirects != 10 {
        return TestResult::Fail;
    }
    if options.timeout_ms != 30_000 {
        return TestResult::Fail;
    }
    if options.verbose {
        return TestResult::Fail;
    }
    if !options.keep_alive {
        return TestResult::Fail;
    }
    if !options.use_cookies {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_request_options_with_method() -> TestResult {
    let options = HttpRequestOptions { method: HttpMethod::Post, ..HttpRequestOptions::default() };
    if options.method != HttpMethod::Post {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_request_options_with_headers() -> TestResult {
    let options = HttpRequestOptions {
        headers: vec![
            (String::from("Content-Type"), String::from("application/json")),
            (String::from("Authorization"), String::from("Bearer token")),
        ],
        ..HttpRequestOptions::default()
    };
    if options.headers.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_request_options_with_body() -> TestResult {
    let options =
        HttpRequestOptions { body: Some(vec![1, 2, 3, 4]), ..HttpRequestOptions::default() };
    if !options.body.is_some() {
        return TestResult::Fail;
    }
    if options.body.as_ref().unwrap().len() != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_request_options_no_redirects() -> TestResult {
    let options = HttpRequestOptions { follow_redirects: false, ..HttpRequestOptions::default() };
    if options.follow_redirects {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_request_options_custom_timeout() -> TestResult {
    let options = HttpRequestOptions { timeout_ms: 60_000, ..HttpRequestOptions::default() };
    if options.timeout_ms != 60_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_request_options_verbose() -> TestResult {
    let options = HttpRequestOptions { verbose: true, ..HttpRequestOptions::default() };
    if !options.verbose {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_request_options_no_keep_alive() -> TestResult {
    let options = HttpRequestOptions { keep_alive: false, ..HttpRequestOptions::default() };
    if options.keep_alive {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_request_options_no_cookies() -> TestResult {
    let options = HttpRequestOptions { use_cookies: false, ..HttpRequestOptions::default() };
    if options.use_cookies {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_request_options_clone() -> TestResult {
    let options = HttpRequestOptions {
        method: HttpMethod::Put,
        timeout_ms: 5000,
        ..HttpRequestOptions::default()
    };
    let cloned = options.clone();
    if options.method != cloned.method {
        return TestResult::Fail;
    }
    if options.timeout_ms != cloned.timeout_ms {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_new() -> TestResult {
    let response = HttpResponse::new();
    if response.status_code != 0 {
        return TestResult::Fail;
    }
    if !response.status_text.is_empty() {
        return TestResult::Fail;
    }
    if !response.headers.is_empty() {
        return TestResult::Fail;
    }
    if !response.body.is_empty() {
        return TestResult::Fail;
    }
    if !response.final_url.is_empty() {
        return TestResult::Fail;
    }
    if response.redirects != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_success() -> TestResult {
    let response = HttpResponse {
        status_code: 200,
        status_text: String::from("OK"),
        headers: Vec::new(),
        body: Vec::new(),
        final_url: String::from("https://example.com"),
        redirects: 0,
    };
    if !response.is_success() {
        return TestResult::Fail;
    }
    if response.is_redirect() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_success_range() -> TestResult {
    for code in 200..300 {
        let response = HttpResponse { status_code: code, ..HttpResponse::new() };
        if !response.is_success() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_not_success() -> TestResult {
    for code in [100, 199, 300, 400, 404, 500, 503] {
        let response = HttpResponse { status_code: code, ..HttpResponse::new() };
        if response.is_success() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_redirect_301() -> TestResult {
    let response = HttpResponse { status_code: 301, ..HttpResponse::new() };
    if !response.is_redirect() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_redirect_302() -> TestResult {
    let response = HttpResponse { status_code: 302, ..HttpResponse::new() };
    if !response.is_redirect() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_redirect_303() -> TestResult {
    let response = HttpResponse { status_code: 303, ..HttpResponse::new() };
    if !response.is_redirect() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_redirect_307() -> TestResult {
    let response = HttpResponse { status_code: 307, ..HttpResponse::new() };
    if !response.is_redirect() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_redirect_308() -> TestResult {
    let response = HttpResponse { status_code: 308, ..HttpResponse::new() };
    if !response.is_redirect() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_not_redirect() -> TestResult {
    for code in [200, 201, 400, 404, 500] {
        let response = HttpResponse { status_code: code, ..HttpResponse::new() };
        if response.is_redirect() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_header_found() -> TestResult {
    let response = HttpResponse {
        status_code: 200,
        headers: vec![
            (String::from("Content-Type"), String::from("text/html")),
            (String::from("Content-Length"), String::from("1234")),
        ],
        ..HttpResponse::new()
    };
    if response.header("Content-Type") != Some("text/html") {
        return TestResult::Fail;
    }
    if response.header("content-type") != Some("text/html") {
        return TestResult::Fail;
    }
    if response.header("CONTENT-TYPE") != Some("text/html") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_header_not_found() -> TestResult {
    let response = HttpResponse {
        status_code: 200,
        headers: vec![(String::from("Content-Type"), String::from("text/html"))],
        ..HttpResponse::new()
    };
    if !response.header("X-Custom-Header").is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_content_length() -> TestResult {
    let response = HttpResponse {
        status_code: 200,
        headers: vec![(String::from("Content-Length"), String::from("5678"))],
        ..HttpResponse::new()
    };
    if response.content_length() != Some(5678) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_content_length_none() -> TestResult {
    let response = HttpResponse::new();
    if !response.content_length().is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_content_type() -> TestResult {
    let response = HttpResponse {
        status_code: 200,
        headers: vec![(String::from("Content-Type"), String::from("application/json"))],
        ..HttpResponse::new()
    };
    if response.content_type() != Some("application/json") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_location() -> TestResult {
    let response = HttpResponse {
        status_code: 302,
        headers: vec![(String::from("Location"), String::from("https://example.com/new"))],
        ..HttpResponse::new()
    };
    if response.location() != Some("https://example.com/new") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_body_text() -> TestResult {
    let response =
        HttpResponse { status_code: 200, body: b"Hello, World!".to_vec(), ..HttpResponse::new() };
    if response.body_text() != Some(String::from("Hello, World!")) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_body_text_invalid_utf8() -> TestResult {
    let response =
        HttpResponse { status_code: 200, body: vec![0xFF, 0xFE, 0x00], ..HttpResponse::new() };
    if !response.body_text().is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_is_keep_alive_true() -> TestResult {
    let response = HttpResponse {
        status_code: 200,
        headers: vec![(String::from("Connection"), String::from("keep-alive"))],
        ..HttpResponse::new()
    };
    if !response.is_keep_alive() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_is_keep_alive_false() -> TestResult {
    let response = HttpResponse {
        status_code: 200,
        headers: vec![(String::from("Connection"), String::from("close"))],
        ..HttpResponse::new()
    };
    if response.is_keep_alive() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_is_keep_alive_no_header() -> TestResult {
    let response = HttpResponse::new();
    if response.is_keep_alive() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_set_cookie_headers() -> TestResult {
    let response = HttpResponse {
        status_code: 200,
        headers: vec![
            (String::from("Set-Cookie"), String::from("session=abc123")),
            (String::from("Set-Cookie"), String::from("user=john")),
            (String::from("Content-Type"), String::from("text/html")),
        ],
        ..HttpResponse::new()
    };
    let cookies = response.get_set_cookie_headers();
    if cookies.len() != 2 {
        return TestResult::Fail;
    }
    if !cookies.contains(&"session=abc123") {
        return TestResult::Fail;
    }
    if !cookies.contains(&"user=john") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_no_set_cookie_headers() -> TestResult {
    let response = HttpResponse::new();
    let cookies = response.get_set_cookie_headers();
    if !cookies.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_clone() -> TestResult {
    let response = HttpResponse {
        status_code: 200,
        status_text: String::from("OK"),
        headers: vec![(String::from("Content-Type"), String::from("text/html"))],
        body: vec![1, 2, 3],
        final_url: String::from("https://example.com"),
        redirects: 2,
    };
    let cloned = response.clone();
    if response.status_code != cloned.status_code {
        return TestResult::Fail;
    }
    if response.body != cloned.body {
        return TestResult::Fail;
    }
    if response.redirects != cloned.redirects {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_response_debug() -> TestResult {
    let response = HttpResponse { status_code: 404, ..HttpResponse::new() };
    let debug_str = alloc::format!("{:?}", response);
    if !debug_str.contains("HttpResponse") {
        return TestResult::Fail;
    }
    if !debug_str.contains("404") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_http_method_all_variants() -> TestResult {
    let methods =
        [HttpMethod::Get, HttpMethod::Head, HttpMethod::Post, HttpMethod::Put, HttpMethod::Delete];
    for method in methods {
        let cloned = method.clone();
        if method != cloned {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
