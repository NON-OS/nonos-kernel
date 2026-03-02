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

use alloc::{collections::BTreeMap, string::String, vec::Vec, format};
use super::types::{PrivilegeLevel, UID_ROOT, UID_ANONYMOUS, SALT_SIZE};
use super::helpers::{derive_password_hash, constant_time_compare};
use crate::crypto::rng::fill_random_bytes;

#[derive(Debug, Clone)]
pub struct UserAccount {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub username: String,
    pub fullname: Option<String>,
    pub home: String,
    pub shell: String,
    password_hash: [u8; 32],
    password_salt: [u8; SALT_SIZE],
    pub locked: bool,
    pub privilege: PrivilegeLevel,
    pub last_login: u64,
    pub failed_attempts: u32,
    pub env: BTreeMap<String, String>,
}

impl UserAccount {
    pub fn new(uid: u32, gid: u32, username: &str, password: &str) -> Self {
        let mut salt = [0u8; SALT_SIZE];
        fill_random_bytes(&mut salt);

        let hash = derive_password_hash(password.as_bytes(), &salt);

        let privilege = match uid {
            UID_ROOT => PrivilegeLevel::Root,
            UID_ANONYMOUS => PrivilegeLevel::Anonymous,
            _ => PrivilegeLevel::User,
        };

        Self {
            uid,
            gid,
            groups: Vec::new(),
            username: String::from(username),
            fullname: None,
            home: format!("/home/{}", username),
            shell: String::from("/bin/sh"),
            password_hash: hash,
            password_salt: salt,
            locked: false,
            privilege,
            last_login: 0,
            failed_attempts: 0,
            env: BTreeMap::new(),
        }
    }

    pub fn verify_password(&self, password: &str) -> bool {
        if self.locked {
            return false;
        }
        let hash = derive_password_hash(password.as_bytes(), &self.password_salt);
        constant_time_compare(&hash, &self.password_hash)
    }

    pub fn change_password(&mut self, new_password: &str) {
        fill_random_bytes(&mut self.password_salt);
        self.password_hash = derive_password_hash(new_password.as_bytes(), &self.password_salt);
    }

    pub fn has_privilege(&self, required: PrivilegeLevel) -> bool {
        match self.privilege {
            PrivilegeLevel::Root => true,
            PrivilegeLevel::Admin => required != PrivilegeLevel::Root,
            PrivilegeLevel::User => {
                matches!(required, PrivilegeLevel::User | PrivilegeLevel::Guest | PrivilegeLevel::Anonymous)
            }
            PrivilegeLevel::Guest => {
                matches!(required, PrivilegeLevel::Guest | PrivilegeLevel::Anonymous)
            }
            PrivilegeLevel::Anonymous => required == PrivilegeLevel::Anonymous,
        }
    }

    pub fn in_group(&self, gid: u32) -> bool {
        self.gid == gid || self.groups.contains(&gid)
    }
}
