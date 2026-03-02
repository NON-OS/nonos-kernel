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

use alloc::{string::String, vec::Vec};
use super::types::UID_ANONYMOUS;
use super::manager::SessionManager;

static SESSION_MANAGER: SessionManager = SessionManager::new();

pub fn session_manager() -> &'static SessionManager {
    &SESSION_MANAGER
}

pub fn init() -> Result<(), &'static str> {
    SESSION_MANAGER.init();
    SESSION_MANAGER.login_anonymous();
    crate::log_info!("Session manager initialized (ZeroState mode)");
    Ok(())
}

pub fn current_uid() -> u32 {
    SESSION_MANAGER.current()
        .map(|s| s.uid)
        .unwrap_or(UID_ANONYMOUS)
}

pub fn current_username() -> String {
    SESSION_MANAGER.current()
        .map(|s| s.username)
        .unwrap_or_else(|| String::from("anonymous"))
}

pub fn current_cwd() -> String {
    SESSION_MANAGER.current()
        .map(|s| s.cwd)
        .unwrap_or_else(|| String::from("/"))
}

pub fn getenv(key: &str) -> Option<String> {
    let session = SESSION_MANAGER.current()?;
    session.env.get(key).cloned()
}

pub fn setenv(key: &str, value: &str) {
    if let Some(session) = SESSION_MANAGER.current() {
        let _ = SESSION_MANAGER.set_env(session.id, key, value);
    }
}

pub fn chdir(path: &str) -> Result<(), &'static str> {
    let session = SESSION_MANAGER.current().ok_or("No active session")?;
    SESSION_MANAGER.chdir(session.id, path)
}

pub fn environ() -> Vec<(String, String)> {
    SESSION_MANAGER.current()
        .map(|s| s.env.into_iter().collect())
        .unwrap_or_default()
}

#[derive(Debug, Clone)]
pub struct SessionStats {
    pub total_users: usize,
    pub active_sessions: usize,
    pub current_uid: u32,
    pub current_username: String,
}

pub fn get_stats() -> SessionStats {
    SessionStats {
        total_users: SESSION_MANAGER.user_count(),
        active_sessions: SESSION_MANAGER.session_count(),
        current_uid: current_uid(),
        current_username: current_username(),
    }
}
