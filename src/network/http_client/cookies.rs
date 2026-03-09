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

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::Mutex;

#[derive(Clone, Debug)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub expires_ms: Option<u64>,
    pub secure: bool,
    pub http_only: bool,
}

pub struct CookieJar {
    cookies: BTreeMap<String, Cookie>,
}

impl CookieJar {
    pub const fn new() -> Self {
        Self {
            cookies: BTreeMap::new(),
        }
    }

    pub fn set(&mut self, cookie: Cookie) {
        let key = format!("{}:{}:{}", cookie.domain, cookie.path, cookie.name);
        self.cookies.insert(key, cookie);
    }

    pub fn get_for_request(&self, domain: &str, path: &str, secure: bool) -> Vec<&Cookie> {
        let now_ms = crate::time::timestamp_millis();

        self.cookies.values()
            .filter(|c| {
                if let Some(exp) = c.expires_ms {
                    if now_ms > exp { return false; }
                }
                if c.secure && !secure { return false; }
                if !domain.ends_with(&c.domain) && c.domain != domain { return false; }
                if !path.starts_with(&c.path) { return false; }
                true
            })
            .collect()
    }

    pub fn build_cookie_header(&self, domain: &str, path: &str, secure: bool) -> Option<String> {
        let cookies = self.get_for_request(domain, path, secure);
        if cookies.is_empty() { return None; }

        let pairs: Vec<String> = cookies.iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect();

        Some(pairs.join("; "))
    }

    pub fn parse_set_cookie(&mut self, header_value: &str, request_domain: &str, request_path: &str) {
        let parts: Vec<&str> = header_value.split(';').collect();
        if parts.is_empty() { return; }

        let name_value = parts[0].trim();
        let eq_pos = match name_value.find('=') {
            Some(p) => p,
            None => return,
        };

        let name = name_value[..eq_pos].trim().to_string();
        let value = name_value[eq_pos + 1..].trim().to_string();

        let mut cookie = Cookie {
            name,
            value,
            domain: request_domain.to_string(),
            path: request_path.to_string(),
            expires_ms: None,
            secure: false,
            http_only: false,
        };

        for attr in parts.iter().skip(1) {
            let attr = attr.trim().to_ascii_lowercase();
            if attr.starts_with("domain=") {
                let d = attr[7..].trim();
                cookie.domain = if d.starts_with('.') {
                    d[1..].to_string()
                } else {
                    d.to_string()
                };
            } else if attr.starts_with("path=") {
                cookie.path = attr[5..].trim().to_string();
            } else if attr.starts_with("max-age=") {
                if let Ok(secs) = attr[8..].trim().parse::<u64>() {
                    cookie.expires_ms = Some(crate::time::timestamp_millis() + secs * 1000);
                }
            } else if attr == "secure" {
                cookie.secure = true;
            } else if attr == "httponly" {
                cookie.http_only = true;
            }
        }

        self.set(cookie);
    }

    pub fn clear(&mut self) {
        self.cookies.clear();
    }

    pub fn clear_expired(&mut self) {
        let now_ms = crate::time::timestamp_millis();
        self.cookies.retain(|_, c| {
            c.expires_ms.map_or(true, |exp| now_ms <= exp)
        });
    }
}

static GLOBAL_COOKIE_JAR: Mutex<CookieJar> = Mutex::new(CookieJar::new());

pub fn get_cookie_jar() -> &'static Mutex<CookieJar> {
    &GLOBAL_COOKIE_JAR
}

pub fn clear_all_cookies() {
    GLOBAL_COOKIE_JAR.lock().clear();
}
