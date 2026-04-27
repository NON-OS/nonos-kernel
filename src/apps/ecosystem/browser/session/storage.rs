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

use super::cookie::Cookie;
use super::types::BrowserSession;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

impl BrowserSession {
    pub fn set_cookie(&mut self, cookie: Cookie) {
        if self.is_private {
            return;
        }
        let key = format!("{}:{}:{}", cookie.domain, cookie.path, cookie.name);
        self.storage.cookies.insert(key, cookie);
    }

    pub fn get_cookies(&self, domain: &str, path: &str) -> Vec<&Cookie> {
        self.storage
            .cookies
            .values()
            .filter(|c| c.matches_domain(domain) && c.matches_path(path) && !c.is_expired())
            .collect()
    }

    pub fn remove_cookie(&mut self, domain: &str, name: &str) {
        let key_prefix = format!("{}:", domain);
        let key_suffix = format!(":{}", name);
        self.storage
            .cookies
            .retain(|key, _| !(key.starts_with(&key_prefix) && key.ends_with(&key_suffix)));
    }

    pub fn clear_cookies(&mut self) {
        self.storage.cookies.clear();
    }

    pub fn set_local_storage(&mut self, origin: &str, key: &str, value: &str) {
        if self.is_private {
            return;
        }
        let storage =
            self.storage.local_storage.entry(String::from(origin)).or_insert_with(BTreeMap::new);
        storage.insert(String::from(key), String::from(value));
    }

    pub fn get_local_storage(&self, origin: &str, key: &str) -> Option<&String> {
        self.storage.local_storage.get(origin).and_then(|s| s.get(key))
    }

    pub fn remove_local_storage(&mut self, origin: &str, key: &str) {
        if let Some(storage) = self.storage.local_storage.get_mut(origin) {
            storage.remove(key);
        }
    }

    pub fn clear_local_storage(&mut self, origin: &str) {
        self.storage.local_storage.remove(origin);
    }

    pub fn set_session_storage(&mut self, origin: &str, key: &str, value: &str) {
        let storage =
            self.storage.session_storage.entry(String::from(origin)).or_insert_with(BTreeMap::new);
        storage.insert(String::from(key), String::from(value));
    }

    pub fn get_session_storage(&self, origin: &str, key: &str) -> Option<&String> {
        self.storage.session_storage.get(origin).and_then(|s| s.get(key))
    }

    pub fn clear_session_storage(&mut self) {
        self.storage.session_storage.clear();
    }
}
