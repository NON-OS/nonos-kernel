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

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use spin::RwLock;

static SESSION_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
static SESSIONS: RwLock<BTreeMap<u64, BrowserSession>> = RwLock::new(BTreeMap::new());
static ACTIVE_SESSION: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct BrowserSession {
    pub id: u64,
    pub name: String,
    pub created_at: u64,
    pub last_active: u64,
    pub is_private: bool,
    pub tabs: Vec<SessionTab>,
    pub storage: SessionStorage,
}

#[derive(Debug, Clone)]
pub struct SessionTab {
    pub url: String,
    pub title: String,
    pub scroll_position: u32,
}

#[derive(Debug, Clone, Default)]
pub struct SessionStorage {
    pub cookies: BTreeMap<String, Cookie>,
    pub local_storage: BTreeMap<String, BTreeMap<String, String>>,
    pub session_storage: BTreeMap<String, BTreeMap<String, String>>,
}

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

        if self.domain.starts_with('.') && domain.ends_with(&self.domain) {
            return true;
        }

        if domain.ends_with(&alloc::format!(".{}", self.domain)) {
            return true;
        }

        false
    }

    pub fn matches_path(&self, path: &str) -> bool {
        path.starts_with(&self.path)
    }

    pub fn to_header_value(&self) -> String {
        alloc::format!("{}={}", self.name, self.value)
    }
}

impl BrowserSession {
    pub fn new(name: &str, is_private: bool) -> Self {
        let id = SESSION_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let now = crate::time::timestamp_secs();

        Self {
            id,
            name: String::from(name),
            created_at: now,
            last_active: now,
            is_private,
            tabs: Vec::new(),
            storage: SessionStorage::default(),
        }
    }

    pub fn add_tab(&mut self, url: &str, title: &str) {
        self.tabs.push(SessionTab {
            url: String::from(url),
            title: String::from(title),
            scroll_position: 0,
        });
        self.touch();
    }

    pub fn remove_tab(&mut self, index: usize) -> bool {
        if index < self.tabs.len() {
            self.tabs.remove(index);
            self.touch();
            true
        } else {
            false
        }
    }

    pub fn update_tab(&mut self, index: usize, url: &str, title: &str) {
        if let Some(tab) = self.tabs.get_mut(index) {
            tab.url = String::from(url);
            tab.title = String::from(title);
            self.touch();
        }
    }

    pub fn touch(&mut self) {
        self.last_active = crate::time::timestamp_secs();
    }

    pub fn set_cookie(&mut self, cookie: Cookie) {
        if self.is_private {
            return;
        }

        let key = alloc::format!("{}:{}:{}", cookie.domain, cookie.path, cookie.name);
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
        let key_prefix = alloc::format!("{}:", domain);
        let key_suffix = alloc::format!(":{}", name);

        self.storage.cookies.retain(|key, _| {
            !(key.starts_with(&key_prefix) && key.ends_with(&key_suffix))
        });
    }

    pub fn clear_cookies(&mut self) {
        self.storage.cookies.clear();
    }

    pub fn set_local_storage(&mut self, origin: &str, key: &str, value: &str) {
        if self.is_private {
            return;
        }

        let storage = self
            .storage
            .local_storage
            .entry(String::from(origin))
            .or_insert_with(BTreeMap::new);
        storage.insert(String::from(key), String::from(value));
    }

    pub fn get_local_storage(&self, origin: &str, key: &str) -> Option<&String> {
        self.storage
            .local_storage
            .get(origin)
            .and_then(|s| s.get(key))
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
        let storage = self
            .storage
            .session_storage
            .entry(String::from(origin))
            .or_insert_with(BTreeMap::new);
        storage.insert(String::from(key), String::from(value));
    }

    pub fn get_session_storage(&self, origin: &str, key: &str) -> Option<&String> {
        self.storage
            .session_storage
            .get(origin)
            .and_then(|s| s.get(key))
    }

    pub fn clear_session_storage(&mut self) {
        self.storage.session_storage.clear();
    }

    pub fn clear_all_storage(&mut self) {
        self.storage.cookies.clear();
        self.storage.local_storage.clear();
        self.storage.session_storage.clear();
    }
}

pub fn create_session(name: &str, is_private: bool) -> u64 {
    let session = BrowserSession::new(name, is_private);
    let id = session.id;

    let mut sessions = SESSIONS.write();
    sessions.insert(id, session);

    if ACTIVE_SESSION.load(Ordering::Relaxed) == 0 {
        ACTIVE_SESSION.store(id, Ordering::SeqCst);
    }

    id
}

pub fn get_session(id: u64) -> Option<BrowserSession> {
    let sessions = SESSIONS.read();
    sessions.get(&id).cloned()
}

pub fn get_active_session() -> Option<BrowserSession> {
    let id = ACTIVE_SESSION.load(Ordering::Relaxed);
    if id == 0 {
        return None;
    }
    get_session(id)
}

pub fn set_active_session(id: u64) -> bool {
    let sessions = SESSIONS.read();
    if sessions.contains_key(&id) {
        ACTIVE_SESSION.store(id, Ordering::SeqCst);
        true
    } else {
        false
    }
}

pub fn destroy_session(id: u64) -> bool {
    let mut sessions = SESSIONS.write();

    if sessions.remove(&id).is_some() {
        if ACTIVE_SESSION.load(Ordering::Relaxed) == id {
            let new_active = sessions.keys().next().copied().unwrap_or(0);
            ACTIVE_SESSION.store(new_active, Ordering::SeqCst);
        }
        true
    } else {
        false
    }
}

pub fn list_sessions() -> Vec<(u64, String, bool)> {
    let sessions = SESSIONS.read();
    sessions
        .values()
        .map(|s| (s.id, s.name.clone(), s.is_private))
        .collect()
}

pub fn update_session<F>(id: u64, f: F)
where
    F: FnOnce(&mut BrowserSession),
{
    let mut sessions = SESSIONS.write();
    if let Some(session) = sessions.get_mut(&id) {
        f(session);
    }
}

pub fn session_count() -> usize {
    SESSIONS.read().len()
}

pub fn clear_expired_cookies() {
    let mut sessions = SESSIONS.write();
    for session in sessions.values_mut() {
        session.storage.cookies.retain(|_, c| !c.is_expired());
    }
}

pub fn parse_set_cookie(header: &str, domain: &str) -> Option<Cookie> {
    let parts: Vec<&str> = header.split(';').collect();
    if parts.is_empty() {
        return None;
    }

    let name_value: Vec<&str> = parts[0].splitn(2, '=').collect();
    if name_value.len() != 2 {
        return None;
    }

    let name = name_value[0].trim();
    let value = name_value[1].trim();

    let mut cookie = Cookie::new(name, value, domain);

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
    cookies
        .iter()
        .map(|c| c.to_header_value())
        .collect::<Vec<_>>()
        .join("; ")
}
