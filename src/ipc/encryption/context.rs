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
use alloc::string::{String, ToString};

pub struct CryptoContext {
    master_key: [u8; 32],
    identity_keys: BTreeMap<String, [u8; 32]>,
    shared_secrets: BTreeMap<(String, String), [u8; 32]>,
}

impl CryptoContext {
    pub fn new(master_key: [u8; 32]) -> Self {
        Self { master_key, identity_keys: BTreeMap::new(), shared_secrets: BTreeMap::new() }
    }

    pub fn get_master_key(&self) -> &[u8; 32] {
        &self.master_key
    }

    pub fn cache_identity_key(&mut self, identity: String, key: [u8; 32]) {
        self.identity_keys.insert(identity, key);
    }

    pub fn get_cached_identity_key(&self, identity: &str) -> Option<[u8; 32]> {
        self.identity_keys.get(identity).copied()
    }

    pub fn cache_shared_secret(&mut self, sender: String, receiver: String, secret: [u8; 32]) {
        let key = if sender < receiver { (sender, receiver) } else { (receiver, sender) };
        self.shared_secrets.insert(key, secret);
    }

    pub fn get_cached_shared_secret(&self, sender: &str, receiver: &str) -> Option<[u8; 32]> {
        let key = if sender < receiver {
            (sender.to_string(), receiver.to_string())
        } else {
            (receiver.to_string(), sender.to_string())
        };
        self.shared_secrets.get(&key).copied()
    }
}
