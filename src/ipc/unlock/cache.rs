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
use super::types::{CachedToken, TokenState, UnlockResponse};
use alloc::collections::BTreeMap;
use spin::RwLock;

type CacheKey = ([u8; 32], [u8; 20]);
static CACHE: RwLock<Option<BTreeMap<CacheKey, CachedToken>>> = RwLock::new(None);

pub fn init_cache() {
    *CACHE.write() = Some(BTreeMap::new());
}

pub fn get(capsule_id: &[u8; 32], wallet: &[u8; 20]) -> Option<UnlockResponse> {
    let key = (*capsule_id, *wallet);
    CACHE
        .read()
        .as_ref()?
        .get(&key)
        .filter(|t| t.state == TokenState::Valid)
        .map(|t| t.response.clone())
}

pub fn insert(capsule_id: [u8; 32], wallet: [u8; 20], response: UnlockResponse, now: u64) {
    let key = (capsule_id, wallet);
    if let Some(c) = CACHE.write().as_mut() {
        c.insert(key, CachedToken::new(response, now));
    }
}

pub fn invalidate(capsule_id: &[u8; 32], wallet: &[u8; 20]) {
    let key = (*capsule_id, *wallet);
    if let Some(c) = CACHE.write().as_mut() {
        if let Some(t) = c.get_mut(&key) {
            t.state = TokenState::Revoked;
        }
    }
}

pub fn cleanup_expired(now: u64) {
    if let Some(c) = CACHE.write().as_mut() {
        c.retain(|_, t| !t.response.is_expired(now) && t.state == TokenState::Valid);
    }
}

pub fn count() -> usize {
    CACHE.read().as_ref().map(|c| c.len()).unwrap_or(0)
}
