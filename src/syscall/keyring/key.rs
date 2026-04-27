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

use super::types::{KeySerial, KeyType, KEY_POS_ALL, KEY_USR_ALL};
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone)]
pub struct Key {
    pub serial: KeySerial,
    pub key_type: KeyType,
    pub description: String,
    pub payload: Vec<u8>,
    pub permissions: u32,
    pub uid: u32,
    pub gid: u32,
    pub expiry: Option<u64>,
    pub revoked: bool,
    pub links: Vec<KeySerial>,
}

impl Key {
    pub fn new(
        serial: KeySerial,
        key_type: KeyType,
        description: String,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            serial,
            key_type,
            description,
            payload,
            permissions: KEY_POS_ALL | KEY_USR_ALL,
            uid: 0,
            gid: 0,
            expiry: None,
            revoked: false,
            links: Vec::new(),
        }
    }

    pub fn is_keyring(&self) -> bool {
        self.key_type == KeyType::Keyring
    }

    pub fn is_valid(&self) -> bool {
        !self.revoked
            && self.expiry.map(|e| e > crate::sys::clock::system_time_secs()).unwrap_or(true)
    }
}
