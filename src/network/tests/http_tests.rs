// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::network::http_client::request::{HttpMethod, HttpRequestOptions};
use crate::network::http_client::response::HttpResponse;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::vec;

#[test]
fn test_http_method_get() {
    let method = HttpMethod::Get;
    assert_eq!(method, HttpMethod::Get);
}

#[test]
fn test_http_method_head() {
    let method = HttpMethod::Head;
    assert_eq!(method, HttpMethod::Head);
}

#[test]
fn test_http_method_post() {
    let method = HttpMethod::Post;
    assert_eq!(method, HttpMethod::Post);
}

#[test]
fn test_http_method_put() {
    let method = HttpMethod::Put;
    assert_eq!(method, HttpMethod::Put);
}

#[test]
fn test_http_method_delete() {
    let method = HttpMethod::Delete;
    assert_eq!(method, HttpMethod::Delete);
}

#[test]
fn test_http_method_clone() {
    let method = HttpMethod::Get;
    let cloned = method.clone();
    assert_eq!(method, cloned);
}

#[test]
fn test_http_method_copy() {
    let method1 = HttpMethod::Post;
    let method2 = method1;
    assert_eq!(method1, method2);
}

#[test]
fn test_http_method_equality() {
    assert_eq!(HttpMethod::Get, HttpMethod::Get);
    assert_ne!(HttpMethod::Get, HttpMethod::Post);
    assert_ne!(HttpMethod::Put, HttpMethod::Delete);
}

#[test]
fn test_http_method_debug() {
    let method = HttpMethod::Delete;
    let debug_str = alloc::format!("{:?}", method);
    assert!(debug_str.contains("Delete"));
}

#[test]
fn test_http_request_options_default() {
    let options = HttpRequestOptions::default();
    assert_eq!(options.method, HttpMethod::Get);
    assert!(options.headers.is_empty());
    assert!(options.body.is_none());
    assert!(options.follow_redirects);
    assert_eq!(options.max_redirects, 10);
    assert_eq!(options.timeout_ms, 30_000);
    assert!(!options.verbose);
    assert!(options.keep_alive);
    assert!(options.use_cookies);
}

#[test]
fn test_http_request_options_with_method() {
    let options = HttpRequestOptions {
        method: HttpMethod::Post,
        ..HttpRequestOptions::default()
    };
    assert_eq!(options.method, HttpMethod::Post);
}

#[test]
fn test_http_request_options_with_headers() {
    let options = HttpRequestOptions {
        headers: vec![
            (String::from("Content-Type"), String::from("application/json")),
            (String::from("Authorization"), String::from("Bearer token")),
        ],
        ..HttpRequestOptions::default()
    };
    assert_eq!(options.headers.len(), 2);
}

#[test]
fn test_http_request_options_with_body() {
    let options = HttpRequestOptions {
        body: Some(vec![1, 2, 3, 4]),
        ..HttpRequestOptions::default()
    };
    assert!(options.body.is_some());
    assert_eq!(options.body.as_ref().unwrap().len(), 4);
}

#[test]
fn test_http_request_options_no_redirects() {
    let options = HttpRequestOptions {
        follow_redirects: false,
        ..HttpRequestOptions::default()
    };
    assert!(!options.follow_redirects);
}

#[test]
fn test_http_request_options_custom_timeout() {
    let options = HttpRequestOptions {
        timeout_ms: 60_000,
        ..HttpRequestOptions::default()
    };
    assert_eq!(options.timeout_ms, 60_000);
}

#[test]
fn test_http_request_options_verbose() {
    let options = HttpRequestOptions {
        verbose: true,
        ..HttpRequestOptions::default()
    };
    assert!(options.verbose);
}

#[test]
fn test_http_request_options_no_keep_alive() {
    let options = HttpRequestOptions {
        keep_alive: false,
        ..HttpRequestOptions::default()
    };
    assert!(!options.keep_alive);
}

#[test]
fn test_http_request_options_no_cookies() {
    let options = HttpRequestOptions {
        use_cookies: false,
        ..HttpRequestOptions::default()
    };
    assert!(!options.use_cookies);
}

#[test]
fn test_http_request_options_clone() {
    let options = HttpRequestOptions {
        method: HttpMethod::Put,
        timeout_ms: 5000,
        ..HttpRequestOptions::default()
    };
    let cloned = options.clone();
    assert_eq!(options.method, cloned.method);
    assert_eq!(options.timeout_ms, cloned.timeout_ms);
}

#[test]
fn test_http_response_new() {
    let response = HttpResponse::new();
    assert_eq!(response.status_code, 0);
    assert!(response.status_text.is_empty());
    assert!(response.headers.is_empty());
    assert!(response.body.is_empty());
    assert!(response.final_url.is_empty());
    assert_eq!(response.redirects, 0);
}

#[test]
fn test_http_response_success() {
    let response = HttpResponse {
        status_code: 200,
        status_text: String::from("OK"),
        headers: Vec::new(),
        body: Vec::new(),
        final_url: String::from("https://example.com"),
        redirects: 0,
    };
    assert!(response.is_success());
    assert!(!response.is_redirect());
}

#[test]
fn test_http_response_success_range() {
    for code in 200..300 {
        let response = HttpResponse {
            status_code: code,
            ..HttpResponse::new()
        };
        assert!(response.is_success());
    }
}

#[test]
fn test_http_response_not_success() {
    for code in [100, 199, 300, 400, 404, 500, 503] {
        let response = HttpResponse {
            status_code: code,
            ..HttpResponse::new()
        };
        assert!(!response.is_success());
    }
}

#[test]
fn test_http_response_redirect_301() {
    let response = HttpResponse {
        status_code: 301,
        ..HttpResponse::new()
    };
    assert!(response.is_redirect());
}

#[test]
fn test_http_response_redirect_302() {
    let response = HttpResponse {
        status_code: 302,
        ..HttpResponse::new()
    };
    assert!(response.is_redirect());
}

#[test]
fn test_http_response_redirect_303() {
    let response = HttpResponse {
        status_code: 303,
        ..HttpResponse::new()
    };
    assert!(response.is_redirect());
}

#[test]
fn test_http_response_redirect_307() {
    let response = HttpResponse {
        status_code: 307,
        ..HttpResponse::new()
    };
    assert!(response.is_redirect());
}

#[test]
fn test_http_response_redirect_308() {
    let response = HttpResponse {
        status_code: 308,
        ..HttpResponse::new()
    };
    assert!(response.is_redirect());
}

#[test]
fn test_http_response_not_redirect() {
    for code in [200, 201, 400, 404, 500] {
        let response = HttpResponse {
            status_code: code,
            ..HttpResponse::new()
        };
        assert!(!response.is_redirect());
    }
}

#[test]
fn test_http_response_header_found() {
    let response = HttpResponse {
        status_code: 200,
        headers: vec![
            (String::from("Content-Type"), String::from("text/html")),
            (String::from("Content-Length"), String::from("1234")),
        ],
        ..HttpResponse::new()
    };
    assert_eq!(response.header("Content-Type"), Some("text/html"));
    assert_eq!(response.header("content-type"), Some("text/html"));
    assert_eq!(response.header("CONTENT-TYPE"), Some("text/html"));
}

#[test]
fn test_http_response_header_not_found() {
    let response = HttpResponse {
        status_code: 200,
        headers: vec![
            (String::from("Content-Type"), String::from("text/html")),
        ],
        ..HttpResponse::new()
    };
    assert!(response.header("X-Custom-Header").is_none());
}

#[test]
fn test_http_response_content_length() {
    let response = HttpResponse {
        status_code: 200,
        headers: vec![
            (String::from("Content-Length"), String::from("5678")),
        ],
        ..HttpResponse::new()
    };
    assert_eq!(response.content_length(), Some(5678));
}

#[test]
fn test_http_response_content_length_none() {
    let response = HttpResponse::new();
    assert!(response.content_length().is_none());
}

#[test]
fn test_http_response_content_type() {
    let response = HttpResponse {
        status_code: 200,
        headers: vec![
            (String::from("Content-Type"), String::from("application/json")),
        ],
        ..HttpResponse::new()
    };
    assert_eq!(response.content_type(), Some("application/json"));
}

#[test]
fn test_http_response_location() {
    let response = HttpResponse {
        status_code: 302,
        headers: vec![
            (String::from("Location"), String::from("https://example.com/new")),
        ],
        ..HttpResponse::new()
    };
    assert_eq!(response.location(), Some("https://example.com/new"));
}

#[test]
fn test_http_response_body_text() {
    let response = HttpResponse {
        status_code: 200,
        body: b"Hello, World!".to_vec(),
        ..HttpResponse::new()
    };
    assert_eq!(response.body_text(), Some(String::from("Hello, World!")));
}

#[test]
fn test_http_response_body_text_invalid_utf8() {
    let response = HttpResponse {
        status_code: 200,
        body: vec![0xFF, 0xFE, 0x00],
        ..HttpResponse::new()
    };
    assert!(response.body_text().is_none());
}

#[test]
fn test_http_response_is_keep_alive_true() {
    let response = HttpResponse {
        status_code: 200,
        headers: vec![
            (String::from("Connection"), String::from("keep-alive")),
        ],
        ..HttpResponse::new()
    };
    assert!(response.is_keep_alive());
}

#[test]
fn test_http_response_is_keep_alive_false() {
    let response = HttpResponse {
        status_code: 200,
        headers: vec![
            (String::from("Connection"), String::from("close")),
        ],
        ..HttpResponse::new()
    };
    assert!(!response.is_keep_alive());
}

#[test]
fn test_http_response_is_keep_alive_no_header() {
    let response = HttpResponse::new();
    assert!(!response.is_keep_alive());
}

#[test]
fn test_http_response_set_cookie_headers() {
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
    assert_eq!(cookies.len(), 2);
    assert!(cookies.contains(&"session=abc123"));
    assert!(cookies.contains(&"user=john"));
}

#[test]
fn test_http_response_no_set_cookie_headers() {
    let response = HttpResponse::new();
    let cookies = response.get_set_cookie_headers();
    assert!(cookies.is_empty());
}

#[test]
fn test_http_response_clone() {
    let response = HttpResponse {
        status_code: 200,
        status_text: String::from("OK"),
        headers: vec![(String::from("Content-Type"), String::from("text/html"))],
        body: vec![1, 2, 3],
        final_url: String::from("https://example.com"),
        redirects: 2,
    };
    let cloned = response.clone();
    assert_eq!(response.status_code, cloned.status_code);
    assert_eq!(response.body, cloned.body);
    assert_eq!(response.redirects, cloned.redirects);
}

#[test]
fn test_http_response_debug() {
    let response = HttpResponse {
        status_code: 404,
        ..HttpResponse::new()
    };
    let debug_str = alloc::format!("{:?}", response);
    assert!(debug_str.contains("HttpResponse"));
    assert!(debug_str.contains("404"));
}

#[test]
fn test_http_method_all_variants() {
    let methods = [
        HttpMethod::Get,
        HttpMethod::Head,
        HttpMethod::Post,
        HttpMethod::Put,
        HttpMethod::Delete,
    ];
    for method in methods {
        let cloned = method.clone();
        assert_eq!(method, cloned);
    }
}

