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
use alloc::string::String;
use alloc::vec::Vec;

pub(super) struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub expires: Option<u64>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: SameSite,
}

#[derive(Clone, Copy, PartialEq)]
pub(super) enum SameSite {
    Strict,
    Lax,
    None,
}

pub struct CookieJar {
    cookies: Vec<Cookie>,
}

impl CookieJar {
    pub fn new() -> Self {
        Self { cookies: Vec::new() }
    }

    pub fn set_cookie(&mut self, cookie_str: &str, url_domain: &str, url_path: &str) {
        if let Some(cookie) =
            super::cookie_parse::parse_set_cookie(cookie_str, url_domain, url_path)
        {
            self.cookies.retain(|c| {
                !(c.name == cookie.name && c.domain == cookie.domain && c.path == cookie.path)
            });
            self.cookies.push(cookie);
        }
    }

    pub fn get_cookies(&self, domain: &str, path: &str, is_secure: bool) -> String {
        let now = crate::time::timestamp_millis() / 1000;
        let mut result = Vec::new();
        for c in &self.cookies {
            if let Some(exp) = c.expires {
                if now > exp {
                    continue;
                }
            }
            if !super::cookie_parse::domain_matches(domain, &c.domain) {
                continue;
            }
            if !path.starts_with(&c.path) {
                continue;
            }
            if c.secure && !is_secure {
                continue;
            }
            result.push(alloc::format!("{}={}", c.name, c.value));
        }
        result.join("; ")
    }

    pub fn get_cookies_for_script(&self, domain: &str, path: &str, is_secure: bool) -> String {
        let now = crate::time::timestamp_millis() / 1000;
        let mut result = Vec::new();
        for c in &self.cookies {
            if c.http_only {
                continue;
            }
            if let Some(exp) = c.expires {
                if now > exp {
                    continue;
                }
            }
            if !super::cookie_parse::domain_matches(domain, &c.domain) {
                continue;
            }
            if !path.starts_with(&c.path) {
                continue;
            }
            if c.secure && !is_secure {
                continue;
            }
            result.push(alloc::format!("{}={}", c.name, c.value));
        }
        result.join("; ")
    }

    pub fn cleanup_expired(&mut self) {
        let now = crate::time::timestamp_millis() / 1000;
        self.cookies.retain(|c| c.expires.map_or(true, |exp| now <= exp));
    }

    pub fn clear(&mut self) {
        self.cookies.clear();
    }

    pub fn remove(&mut self, name: &str, domain: &str, path: &str) {
        self.cookies.retain(|c| !(c.name == name && c.domain == domain && c.path == path));
    }
}
