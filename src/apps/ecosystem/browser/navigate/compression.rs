extern crate alloc;
use alloc::string::String;

pub fn accept_encoding_header() -> String {
    String::from("gzip, deflate")
}

pub fn content_encoding(headers: &[(String, String)]) -> Option<String> {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("content-encoding") {
            return Some(v.clone());
        }
    }
    None
}

pub fn needs_decompression(encoding: &str) -> bool {
    let lower = encoding.to_ascii_lowercase();
    lower == "gzip" || lower == "deflate" || lower == "br"
}

pub fn supports_brotli() -> bool { false }

pub fn supports_gzip() -> bool { true }
