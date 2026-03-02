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

use alloc::{collections::BTreeMap, string::String, format};
use super::types::{PrivilegeLevel, SessionState, TOKEN_SIZE, SESSION_TIMEOUT_TICKS};
use super::account::UserAccount;
use super::helpers::normalize_path;
use crate::crypto::rng::fill_random_bytes;
use crate::time::current_ticks;

#[derive(Debug, Clone)]
pub struct UserSession {
    pub id: u64,
    pub token: [u8; TOKEN_SIZE],
    pub uid: u32,
    pub username: String,
    pub state: SessionState,
    pub created: u64,
    pub last_activity: u64,
    pub cwd: String,
    pub env: BTreeMap<String, String>,
    pub terminal: Option<u32>,
    pub elevated: bool,
    pub pgid: u32,
}

impl UserSession {
    pub fn new(id: u64, user: &UserAccount) -> Self {
        let mut token = [0u8; TOKEN_SIZE];
        fill_random_bytes(&mut token);

        let now = current_ticks();

        let mut env = user.env.clone();
        env.insert(String::from("HOME"), user.home.clone());
        env.insert(String::from("USER"), user.username.clone());
        env.insert(String::from("LOGNAME"), user.username.clone());
        env.insert(String::from("SHELL"), user.shell.clone());
        env.insert(String::from("PATH"), String::from("/bin:/usr/bin:/sbin:/usr/sbin"));
        env.insert(String::from("TERM"), String::from("nonos-term"));

        Self {
            id,
            token,
            uid: user.uid,
            username: user.username.clone(),
            state: SessionState::Active,
            created: now,
            last_activity: now,
            cwd: user.home.clone(),
            env,
            terminal: None,
            elevated: user.privilege == PrivilegeLevel::Root,
            pgid: 0,
        }
    }

    pub fn touch(&mut self) {
        self.last_activity = current_ticks();
        if self.state == SessionState::Idle {
            self.state = SessionState::Active;
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = current_ticks();
        now.saturating_sub(self.last_activity) > SESSION_TIMEOUT_TICKS
    }

    pub fn get_env(&self, key: &str) -> Option<&String> {
        self.env.get(key)
    }

    pub fn set_env(&mut self, key: &str, value: &str) {
        self.env.insert(String::from(key), String::from(value));
    }

    pub fn unset_env(&mut self, key: &str) {
        self.env.remove(key);
    }

    pub fn chdir(&mut self, path: &str) -> Result<(), &'static str> {
        if path.is_empty() {
            return Err("Invalid path");
        }

        let home = self.env.get("HOME").cloned().unwrap_or_else(|| String::from("/"));

        let new_cwd = if path.starts_with('/') {
            String::from(path)
        } else if path == "~" {
            home
        } else if path.starts_with("~/") {
            format!("{}/{}", home, &path[2..])
        } else {
            if self.cwd.ends_with('/') {
                format!("{}{}", self.cwd, path)
            } else {
                format!("{}/{}", self.cwd, path)
            }
        };

        let normalized = normalize_path(&new_cwd);
        self.cwd = normalized.clone();
        self.env.insert(String::from("PWD"), normalized);
        Ok(())
    }
}
