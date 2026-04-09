extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use super::origin::Origin;

#[derive(Debug, Clone)]
pub struct CorsRequest {
    pub origin: Origin,
    pub method: String,
    pub headers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorsResult {
    Allowed,
    Blocked,
    NeedsPreflight,
}

pub fn cors_check(
    request: &CorsRequest,
    allow_origin: Option<&str>,
    allow_methods: Option<&str>,
    allow_headers: Option<&str>,
) -> CorsResult {
    let origin_str = request.origin.serialized();
    match allow_origin {
        None => return CorsResult::Blocked,
        Some("*") => {}
        Some(allowed) => {
            if allowed != origin_str { return CorsResult::Blocked; }
        }
    }
    if needs_preflight(&request.method, &request.headers) {
        if let Some(methods) = allow_methods {
            if !method_allowed(&request.method, methods) { return CorsResult::Blocked; }
        }
        if let Some(headers) = allow_headers {
            for h in &request.headers {
                if !header_allowed(h, headers) { return CorsResult::Blocked; }
            }
        }
    }
    CorsResult::Allowed
}

fn needs_preflight(method: &str, headers: &[String]) -> bool {
    if method != "GET" && method != "HEAD" && method != "POST" {
        return true;
    }
    for h in headers {
        let lower = h.to_ascii_lowercase();
        if lower != "accept" && lower != "accept-language" && lower != "content-language" && lower != "content-type" {
            return true;
        }
    }
    false
}

fn method_allowed(method: &str, allowed: &str) -> bool {
    allowed.split(',').any(|m| m.trim().eq_ignore_ascii_case(method))
}

fn header_allowed(header: &str, allowed: &str) -> bool {
    allowed.split(',').any(|h| h.trim().eq_ignore_ascii_case(header))
}

pub fn exposed_headers(expose_header: Option<&str>) -> Vec<String> {
    let always = ["cache-control", "content-language", "content-type", "expires", "last-modified", "pragma"];
    let mut result: Vec<String> = always.iter().map(|s| String::from(*s)).collect();
    if let Some(extra) = expose_header {
        for h in extra.split(',') {
            let trimmed = String::from(h.trim());
            if !trimmed.is_empty() { result.push(trimmed); }
        }
    }
    result
}
