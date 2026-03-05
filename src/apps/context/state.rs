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

use super::permissions::{AppPermissions, PermissionManager};
use crate::apps::types::{AppId, AppType};

pub struct AppContext {
    id: AppId,
    name: String,
    app_type: AppType,
    permissions: PermissionManager,
    started_at: AtomicU64,
    last_active: AtomicU64,
    memory_used: AtomicU64,
    state: BTreeMap<String, Vec<u8>>,
}

impl AppContext {
    pub fn new(name: String, app_type: AppType, permissions: AppPermissions) -> Self {
        let ctx = Self {
            id: AppId::new(),
            name,
            app_type,
            permissions: PermissionManager::new(),
            started_at: AtomicU64::new(0),
            last_active: AtomicU64::new(0),
            memory_used: AtomicU64::new(0),
            state: BTreeMap::new(),
        };
        ctx.permissions.grant(permissions);
        ctx
    }

    pub const fn id(&self) -> AppId {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn app_type(&self) -> AppType {
        self.app_type
    }

    pub fn permissions(&self) -> &PermissionManager {
        &self.permissions
    }

    pub fn has_permission(&self, perm: AppPermissions) -> bool {
        self.permissions.has(perm)
    }

    pub fn mark_started(&self) {
        let now = crate::time::timestamp_millis();
        self.started_at.store(now, Ordering::Release);
        self.last_active.store(now, Ordering::Release);
    }

    pub fn mark_active(&self) {
        self.last_active.store(crate::time::timestamp_millis(), Ordering::Release);
    }

    pub fn started_at(&self) -> u64 {
        self.started_at.load(Ordering::Acquire)
    }

    pub fn last_active(&self) -> u64 {
        self.last_active.load(Ordering::Acquire)
    }

    pub fn uptime_ms(&self) -> u64 {
        let started = self.started_at.load(Ordering::Acquire);
        if started == 0 {
            return 0;
        }
        crate::time::timestamp_millis().saturating_sub(started)
    }

    pub fn idle_ms(&self) -> u64 {
        let last = self.last_active.load(Ordering::Acquire);
        if last == 0 {
            return 0;
        }
        crate::time::timestamp_millis().saturating_sub(last)
    }

    pub fn add_memory(&self, bytes: u64) {
        self.memory_used.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn free_memory(&self, bytes: u64) {
        self.memory_used.fetch_sub(bytes.min(self.memory_used.load(Ordering::Relaxed)), Ordering::Relaxed);
    }

    pub fn memory_used(&self) -> u64 {
        self.memory_used.load(Ordering::Relaxed)
    }

    pub fn set_state(&mut self, key: String, value: Vec<u8>) {
        self.state.insert(key, value);
    }

    pub fn get_state(&self, key: &str) -> Option<&Vec<u8>> {
        self.state.get(key)
    }

    pub fn remove_state(&mut self, key: &str) -> Option<Vec<u8>> {
        self.state.remove(key)
    }

    pub fn clear_state(&mut self) {
        self.state.clear();
    }

    pub fn state_keys(&self) -> impl Iterator<Item = &String> {
        self.state.keys()
    }
}
