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

use super::cookie::{Cookie, SameSite};
use alloc::string::String;
use alloc::vec::Vec;

pub fn parse_set_cookie(header: &str, domain: &str) -> Option<Cookie> {
    let parts: Vec<&str> = header.split(';').collect();
    if parts.is_empty() {
        return None;
    }
    let name_value: Vec<&str> = parts[0].splitn(2, '=').collect();
    if name_value.len() != 2 {
        return None;
    }
    let mut cookie = Cookie::new(name_value[0].trim(), name_value[1].trim(), domain);
    for part in parts.iter().skip(1) {
        let attr: Vec<&str> = part.splitn(2, '=').collect();
        let attr_name = attr[0].trim().to_ascii_lowercase();
        let attr_value = attr.get(1).map(|v| v.trim());
        match attr_name.as_str() {
            "domain" => {
                if let Some(d) = attr_value {
                    cookie.domain = String::from(d);
                }
            }
            "path" => {
                if let Some(p) = attr_value {
                    cookie.path = String::from(p);
                }
            }
            "max-age" => {
                if let Some(age_str) = attr_value {
                    if let Ok(age) = age_str.parse::<u64>() {
                        cookie.expires = Some(crate::time::timestamp_secs() + age);
                    }
                }
            }
            "secure" => {
                cookie.secure = true;
            }
            "httponly" => {
                cookie.http_only = true;
            }
            "samesite" => {
                if let Some(v) = attr_value {
                    cookie.same_site = match v.to_ascii_lowercase().as_str() {
                        "strict" => SameSite::Strict,
                        "none" => SameSite::None,
                        _ => SameSite::Lax,
                    };
                }
            }
            _ => {}
        }
    }
    Some(cookie)
}

pub fn format_cookie_header(cookies: &[&Cookie]) -> String {
    cookies.iter().map(|c| c.to_header_value()).collect::<Vec<_>>().join("; ")
}
