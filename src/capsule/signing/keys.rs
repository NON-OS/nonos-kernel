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
use spin::RwLock;

pub type PublicKey = [u8; 32];
pub type SecretKey = [u8; 64];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    NotFound,
    InvalidKey,
    AlreadyExists,
}

struct KeyStore {
    trusted: BTreeMap<[u8; 32], TrustedKey>,
}

#[derive(Clone)]
pub struct TrustedKey {
    pub pubkey: PublicKey,
    pub name: [u8; 32],
    pub added_at: u64,
}

static KEYS: RwLock<Option<KeyStore>> = RwLock::new(None);

pub fn init() {
    *KEYS.write() = Some(KeyStore { trusted: BTreeMap::new() });
}

pub fn add_trusted(pubkey: PublicKey, name: [u8; 32]) -> Result<(), KeyError> {
    let mut guard = KEYS.write();
    let store = guard.as_mut().ok_or(KeyError::NotFound)?;
    if store.trusted.contains_key(&pubkey) {
        return Err(KeyError::AlreadyExists);
    }
    let key = TrustedKey { pubkey, name, added_at: crate::time::unix_timestamp() };
    store.trusted.insert(pubkey, key);
    Ok(())
}

pub fn remove_trusted(pubkey: &PublicKey) -> Result<(), KeyError> {
    let mut guard = KEYS.write();
    let store = guard.as_mut().ok_or(KeyError::NotFound)?;
    store.trusted.remove(pubkey).ok_or(KeyError::NotFound)?;
    Ok(())
}

pub fn is_trusted(pubkey: &PublicKey) -> bool {
    KEYS.read().as_ref().map(|s| s.trusted.contains_key(pubkey)).unwrap_or(false)
}

pub fn get_trusted(pubkey: &PublicKey) -> Option<TrustedKey> {
    KEYS.read().as_ref()?.trusted.get(pubkey).cloned()
}

pub fn list_trusted() -> alloc::vec::Vec<TrustedKey> {
    KEYS.read().as_ref().map(|s| s.trusted.values().cloned().collect()).unwrap_or_default()
}

pub fn trusted_count() -> usize {
    KEYS.read().as_ref().map(|s| s.trusted.len()).unwrap_or(0)
}
