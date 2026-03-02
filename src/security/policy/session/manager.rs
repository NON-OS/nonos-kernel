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

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use spin::RwLock;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use super::types::{PrivilegeLevel, SessionState, UID_ROOT, UID_ANONYMOUS, UID_DEFAULT, GID_ROOT, GID_WHEEL, GID_USERS};
use super::account::UserAccount;
use super::session::UserSession;
use crate::time::current_ticks;

pub struct SessionManager {
    users: RwLock<BTreeMap<u32, UserAccount>>,
    username_map: RwLock<BTreeMap<String, u32>>,
    sessions: RwLock<BTreeMap<u64, UserSession>>,
    next_session_id: AtomicU64,
    next_uid: AtomicU32,
    current_session: AtomicU64,
}

impl SessionManager {
    pub const fn new() -> Self {
        Self {
            users: RwLock::new(BTreeMap::new()),
            username_map: RwLock::new(BTreeMap::new()),
            sessions: RwLock::new(BTreeMap::new()),
            next_session_id: AtomicU64::new(1),
            next_uid: AtomicU32::new(UID_DEFAULT),
            current_session: AtomicU64::new(0),
        }
    }

    pub fn init(&self) {
        let mut root = UserAccount::new(UID_ROOT, GID_ROOT, "root", "");
        root.privilege = PrivilegeLevel::Root;
        root.home = String::from("/root");
        root.groups.push(GID_WHEEL);
        self.add_user_internal(root);

        let mut anon = UserAccount::new(UID_ANONYMOUS, GID_USERS, "anonymous", "");
        anon.privilege = PrivilegeLevel::Anonymous;
        anon.home = String::from("/home/anonymous");
        anon.fullname = Some(String::from("Anonymous User"));
        self.add_user_internal(anon);

        let mut zerouser = UserAccount::new(UID_DEFAULT, GID_USERS, "zerostate", "");
        zerouser.privilege = PrivilegeLevel::User;
        zerouser.home = String::from("/home/zerostate");
        zerouser.fullname = Some(String::from("ZeroState User"));
        zerouser.env.insert(String::from("EDITOR"), String::from("nano"));
        self.add_user_internal(zerouser);
    }

    fn add_user_internal(&self, user: UserAccount) {
        let uid = user.uid;
        let username = user.username.clone();
        self.users.write().insert(uid, user);
        self.username_map.write().insert(username, uid);
    }

    pub fn create_user(&self, username: &str, password: &str, privilege: PrivilegeLevel) -> Result<u32, &'static str> {
        if self.username_map.read().contains_key(username) {
            return Err("Username already exists");
        }

        let uid = self.next_uid.fetch_add(1, Ordering::SeqCst);
        let mut user = UserAccount::new(uid, GID_USERS, username, password);
        user.privilege = privilege;
        self.add_user_internal(user);
        Ok(uid)
    }

    pub fn get_user(&self, uid: u32) -> Option<UserAccount> {
        self.users.read().get(&uid).cloned()
    }

    pub fn get_user_by_name(&self, username: &str) -> Option<UserAccount> {
        let uid = *self.username_map.read().get(username)?;
        self.get_user(uid)
    }

    pub fn login(&self, username: &str, password: &str) -> Result<u64, &'static str> {
        let uid = *self.username_map.read().get(username).ok_or("User not found")?;

        let mut users = self.users.write();
        let user = users.get_mut(&uid).ok_or("User not found")?;

        if user.failed_attempts >= 5 {
            return Err("Account locked due to too many failed attempts");
        }

        if !user.verify_password(password) {
            user.failed_attempts += 1;
            return Err("Invalid password");
        }

        user.failed_attempts = 0;
        user.last_login = current_ticks();

        let session_id = self.next_session_id.fetch_add(1, Ordering::SeqCst);
        let session = UserSession::new(session_id, user);

        self.sessions.write().insert(session_id, session);
        self.current_session.store(session_id, Ordering::SeqCst);

        Ok(session_id)
    }

    pub fn login_anonymous(&self) -> u64 {
        if let Some(user) = self.get_user(UID_ANONYMOUS) {
            let session_id = self.next_session_id.fetch_add(1, Ordering::SeqCst);
            let session = UserSession::new(session_id, &user);
            self.sessions.write().insert(session_id, session);
            self.current_session.store(session_id, Ordering::SeqCst);
            session_id
        } else {
            0
        }
    }

    pub fn logout(&self, session_id: u64) -> Result<(), &'static str> {
        let mut sessions = self.sessions.write();
        let session = sessions.get_mut(&session_id).ok_or("Session not found")?;
        session.state = SessionState::Terminated;

        if self.current_session.load(Ordering::SeqCst) == session_id {
            self.current_session.store(0, Ordering::SeqCst);
        }

        sessions.remove(&session_id);
        Ok(())
    }

    pub fn get_session(&self, session_id: u64) -> Option<UserSession> {
        self.sessions.read().get(&session_id).cloned()
    }

    pub fn current(&self) -> Option<UserSession> {
        let session_id = self.current_session.load(Ordering::SeqCst);
        if session_id == 0 { None } else { self.get_session(session_id) }
    }

    pub fn set_current(&self, session_id: u64) {
        self.current_session.store(session_id, Ordering::SeqCst);
    }

    pub fn touch_session(&self, session_id: u64) {
        if let Some(session) = self.sessions.write().get_mut(&session_id) {
            session.touch();
        }
    }

    pub fn cleanup_expired(&self) {
        let mut sessions = self.sessions.write();
        let expired: Vec<u64> = sessions.iter()
            .filter(|(_, s)| s.is_expired())
            .map(|(&id, _)| id)
            .collect();

        for id in expired {
            sessions.remove(&id);
        }
    }

    pub fn list_sessions(&self) -> Vec<(u64, String, SessionState)> {
        self.sessions.read().iter()
            .map(|(&id, s)| (id, s.username.clone(), s.state))
            .collect()
    }

    pub fn get_env(&self, session_id: u64, key: &str) -> Option<String> {
        self.sessions.read().get(&session_id)?.env.get(key).cloned()
    }

    pub fn set_env(&self, session_id: u64, key: &str, value: &str) -> Result<(), &'static str> {
        self.sessions.write()
            .get_mut(&session_id)
            .ok_or("Session not found")?
            .set_env(key, value);
        Ok(())
    }

    pub fn chdir(&self, session_id: u64, path: &str) -> Result<(), &'static str> {
        self.sessions.write()
            .get_mut(&session_id)
            .ok_or("Session not found")?
            .chdir(path)
    }

    pub fn getcwd(&self, session_id: u64) -> Result<String, &'static str> {
        Ok(self.sessions.read()
            .get(&session_id)
            .ok_or("Session not found")?
            .cwd.clone())
    }

    pub fn check_privilege(&self, session_id: u64, required: PrivilegeLevel) -> bool {
        if let Some(session) = self.sessions.read().get(&session_id) {
            if let Some(user) = self.get_user(session.uid) {
                return user.has_privilege(required) || session.elevated;
            }
        }
        false
    }

    pub fn elevate(&self, session_id: u64, root_password: &str) -> Result<(), &'static str> {
        let root = self.get_user(UID_ROOT).ok_or("Root user not found")?;
        if !root.verify_password(root_password) {
            return Err("Invalid root password");
        }

        self.sessions.write()
            .get_mut(&session_id)
            .ok_or("Session not found")?
            .elevated = true;

        Ok(())
    }

    pub fn drop_privileges(&self, session_id: u64) -> Result<(), &'static str> {
        self.sessions.write()
            .get_mut(&session_id)
            .ok_or("Session not found")?
            .elevated = false;
        Ok(())
    }

    pub fn user_count(&self) -> usize {
        self.users.read().len()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }
}
