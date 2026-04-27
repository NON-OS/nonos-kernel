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

use super::types::BrowserSession;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

pub(super) static SESSION_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
static SESSIONS: RwLock<BTreeMap<u64, BrowserSession>> = RwLock::new(BTreeMap::new());
static ACTIVE_SESSION: AtomicU64 = AtomicU64::new(0);

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
    SESSIONS.read().get(&id).cloned()
}

pub fn get_active_session() -> Option<BrowserSession> {
    let id = ACTIVE_SESSION.load(Ordering::Relaxed);
    if id == 0 {
        None
    } else {
        get_session(id)
    }
}

pub fn set_active_session(id: u64) -> bool {
    if SESSIONS.read().contains_key(&id) {
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
    SESSIONS.read().values().map(|s| (s.id, s.name.clone(), s.is_private)).collect()
}

pub fn update_session<F: FnOnce(&mut BrowserSession)>(id: u64, f: F) {
    if let Some(session) = SESSIONS.write().get_mut(&id) {
        f(session);
    }
}

pub fn session_count() -> usize {
    SESSIONS.read().len()
}

pub fn clear_expired_cookies() {
    for session in SESSIONS.write().values_mut() {
        session.storage.cookies.retain(|_, c| !c.is_expired());
    }
}
