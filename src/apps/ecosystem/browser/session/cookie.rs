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

#[derive(Debug, Clone)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub expires: Option<u64>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: SameSite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl Cookie {
    pub fn new(name: &str, value: &str, domain: &str) -> Self {
        Self {
            name: String::from(name),
            value: String::from(value),
            domain: String::from(domain),
            path: String::from("/"),
            expires: None,
            secure: false,
            http_only: false,
            same_site: SameSite::Lax,
        }
    }

    pub fn is_expired(&self) -> bool {
        match self.expires {
            Some(exp) => crate::time::timestamp_secs() > exp,
            None => false,
        }
    }

    pub fn matches_domain(&self, domain: &str) -> bool {
        if self.domain == domain {
            return true;
        }
        let cookie_domain =
            if self.domain.starts_with('.') { &self.domain[1..] } else { &self.domain };
        if cookie_domain.matches('.').count() < 1 {
            return false;
        }
        if domain == cookie_domain {
            return true;
        }
        if domain.ends_with(&format!(".{}", cookie_domain)) {
            return true;
        }
        false
    }

    pub fn matches_path(&self, path: &str) -> bool {
        path.starts_with(&self.path)
    }

    pub fn to_header_value(&self) -> String {
        format!("{}={}", self.name, self.value)
    }
}
