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

extern crate alloc;

use alloc::format;
use alloc::string::String;

/// Percent-encode a string per application/x-www-form-urlencoded (RFC 3986 + space→+).
pub fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

/// Build an application/x-www-form-urlencoded body from name=value pairs.
pub fn build_form_urlencoded(pairs: &[(String, String)]) -> String {
    let mut out = String::new();
    for (i, (name, value)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(&url_encode(name));
        out.push('=');
        out.push_str(&url_encode(value));
    }
    out
}

/// Resolve a possibly-relative action URL against a base URL.
pub fn resolve_url(action: &str, base_url: &str) -> String {
    if action.is_empty() {
        return String::from(base_url);
    }
    // Already absolute
    if action.starts_with("http://") || action.starts_with("https://") {
        return String::from(action);
    }
    // Protocol-relative
    if action.starts_with("//") {
        let scheme = if base_url.starts_with("https") { "https:" } else { "http:" };
        return format!("{}{}", scheme, action);
    }

    // Extract scheme + authority from base
    let scheme_end = base_url.find("://").map(|i| i + 3).unwrap_or(0);
    let authority_end =
        base_url[scheme_end..].find('/').map(|i| i + scheme_end).unwrap_or(base_url.len());

    if action.starts_with('/') {
        // Absolute path
        format!("{}{}", &base_url[..authority_end], action)
    } else {
        // Relative path — append to base directory
        let dir_end = base_url.rfind('/').unwrap_or(authority_end);
        let base_dir = if dir_end >= authority_end {
            &base_url[..dir_end + 1]
        } else {
            &base_url[..authority_end]
        };
        format!("{}{}", base_dir, action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;

    #[test]
    fn test_url_encode_unreserved() {
        assert_eq!(url_encode("hello"), "hello");
        assert_eq!(url_encode("ABC-_.~"), "ABC-_.~");
    }

    #[test]
    fn test_url_encode_space() {
        assert_eq!(url_encode("hello world"), "hello+world");
    }

    #[test]
    fn test_url_encode_special_chars() {
        assert_eq!(url_encode("a=b&c"), "a%3Db%26c");
        assert_eq!(url_encode("100%"), "100%25");
        assert_eq!(url_encode("@#$"), "%40%23%24");
    }

    #[test]
    fn test_url_encode_unicode() {
        // UTF-8 bytes for ñ are 0xC3 0xB1
        assert_eq!(url_encode("ñ"), "%C3%B1");
    }

    #[test]
    fn test_build_form_urlencoded_empty() {
        let pairs: Vec<(String, String)> = Vec::new();
        assert_eq!(build_form_urlencoded(&pairs), "");
    }

    #[test]
    fn test_build_form_urlencoded_single() {
        let pairs = vec![(String::from("q"), String::from("rust lang"))];
        assert_eq!(build_form_urlencoded(&pairs), "q=rust+lang");
    }

    #[test]
    fn test_build_form_urlencoded_multiple() {
        let pairs = vec![
            (String::from("user"), String::from("admin")),
            (String::from("pass"), String::from("s3cr&t")),
        ];
        assert_eq!(build_form_urlencoded(&pairs), "user=admin&pass=s3cr%26t");
    }

    #[test]
    fn test_resolve_url_absolute() {
        assert_eq!(
            resolve_url("https://other.com/path", "https://example.com/"),
            "https://other.com/path"
        );
    }

    #[test]
    fn test_resolve_url_empty_action() {
        assert_eq!(resolve_url("", "https://example.com/page"), "https://example.com/page");
    }

    #[test]
    fn test_resolve_url_absolute_path() {
        assert_eq!(
            resolve_url("/login", "https://example.com/some/page"),
            "https://example.com/login"
        );
    }

    #[test]
    fn test_resolve_url_relative_path() {
        assert_eq!(
            resolve_url("submit", "https://example.com/forms/edit"),
            "https://example.com/forms/submit"
        );
    }

    #[test]
    fn test_resolve_url_protocol_relative() {
        assert_eq!(
            resolve_url("//cdn.example.com/api", "https://example.com/"),
            "https://cdn.example.com/api"
        );
    }
}
