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
use super::cookies::{Cookie, SameSite};
use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn parse_set_cookie(
    s: &str,
    default_domain: &str,
    default_path: &str,
) -> Option<Cookie> {
    let parts: Vec<&str> = s.split(';').collect();
    let name_value = parts.get(0)?;
    let (name, value) = name_value.split_once('=')?;
    let mut cookie = Cookie {
        name: String::from(name.trim()),
        value: String::from(value.trim()),
        domain: String::from(default_domain),
        path: String::from(default_path),
        expires: None,
        secure: false,
        http_only: false,
        same_site: SameSite::Lax,
    };
    for part in parts.iter().skip(1) {
        let part = part.trim().to_lowercase();
        if part == "secure" {
            cookie.secure = true;
        } else if part == "httponly" {
            cookie.http_only = true;
        } else if let Some((attr, val)) = part.split_once('=') {
            match attr.trim() {
                "domain" => cookie.domain = String::from(val.trim().trim_start_matches('.')),
                "path" => cookie.path = String::from(val.trim()),
                "samesite" => {
                    cookie.same_site = match val.trim() {
                        "strict" => SameSite::Strict,
                        "none" => SameSite::None,
                        _ => SameSite::Lax,
                    }
                }
                _ => {}
            }
        }
    }
    Some(cookie)
}

pub(super) fn domain_matches(request_domain: &str, cookie_domain: &str) -> bool {
    if request_domain == cookie_domain {
        return true;
    }
    if request_domain.ends_with(&alloc::format!(".{}", cookie_domain)) {
        return true;
    }
    false
}
