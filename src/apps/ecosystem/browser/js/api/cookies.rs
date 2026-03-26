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
    #[allow(dead_code)] // TODO: implement cookie expiration checking
    pub expires: Option<u64>,
    pub secure: bool,
    #[allow(dead_code)] // TODO: implement HTTP-only cookie handling
    pub http_only: bool,
    pub same_site: SameSite,
}

#[derive(Clone, Copy, PartialEq)]
pub(super) enum SameSite { Strict, Lax, None }

pub struct CookieJar { cookies: Vec<Cookie> }

impl CookieJar {
    pub fn new() -> Self { Self { cookies: Vec::new() } }

    pub fn set_cookie(&mut self, cookie_str: &str, url_domain: &str, url_path: &str) {
        if let Some(cookie) = parse_set_cookie(cookie_str, url_domain, url_path) {
            self.cookies.retain(|c| !(c.name == cookie.name && c.domain == cookie.domain && c.path == cookie.path));
            self.cookies.push(cookie);
        }
    }

    pub fn get_cookies(&self, domain: &str, path: &str, is_secure: bool) -> String {
        let mut result = Vec::new();
        for c in &self.cookies {
            if !domain_matches(domain, &c.domain) { continue; }
            if !path.starts_with(&c.path) { continue; }
            if c.secure && !is_secure { continue; }
            result.push(alloc::format!("{}={}", c.name, c.value));
        }
        result.join("; ")
    }

    pub fn clear(&mut self) { self.cookies.clear(); }
    pub fn remove(&mut self, name: &str, domain: &str, path: &str) { self.cookies.retain(|c| !(c.name == name && c.domain == domain && c.path == path)); }
}

fn parse_set_cookie(s: &str, default_domain: &str, default_path: &str) -> Option<Cookie> {
    let parts: Vec<&str> = s.split(';').collect();
    let name_value = parts.get(0)?;
    let (name, value) = name_value.split_once('=')?;
    let mut cookie = Cookie { name: String::from(name.trim()), value: String::from(value.trim()), domain: String::from(default_domain), path: String::from(default_path), expires: None, secure: false, http_only: false, same_site: SameSite::Lax };
    for part in parts.iter().skip(1) {
        let part = part.trim().to_lowercase();
        if part == "secure" { cookie.secure = true; }
        else if part == "httponly" { cookie.http_only = true; }
        else if let Some((attr, val)) = part.split_once('=') {
            match attr.trim() {
                "domain" => cookie.domain = String::from(val.trim().trim_start_matches('.')),
                "path" => cookie.path = String::from(val.trim()),
                "samesite" => cookie.same_site = match val.trim() { "strict" => SameSite::Strict, "none" => SameSite::None, _ => SameSite::Lax },
                _ => {}
            }
        }
    }
    Some(cookie)
}

fn domain_matches(request_domain: &str, cookie_domain: &str) -> bool {
    if request_domain == cookie_domain { return true; }
    if request_domain.ends_with(&alloc::format!(".{}", cookie_domain)) { return true; }
    false
}
