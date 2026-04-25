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
use super::sandbox::Sandbox;
use super::types::{Capsule, CapsuleId, CapsuleState};
use alloc::collections::BTreeMap;
use spin::RwLock;

struct Registry {
    capsules: BTreeMap<CapsuleId, Capsule>,
    sandboxes: BTreeMap<CapsuleId, Sandbox>,
    pid_map: BTreeMap<u64, CapsuleId>,
}

static REG: RwLock<Option<Registry>> = RwLock::new(None);

pub fn init_registry() {
    *REG.write() = Some(Registry {
        capsules: BTreeMap::new(),
        sandboxes: BTreeMap::new(),
        pid_map: BTreeMap::new(),
    });
}

pub fn insert(c: Capsule) {
    if let Some(r) = REG.write().as_mut() {
        r.capsules.insert(c.id, c);
    }
}

pub fn get(id: CapsuleId) -> Option<Capsule> {
    REG.read().as_ref().and_then(|r| r.capsules.get(&id).cloned())
}

pub fn get_mut(id: CapsuleId) -> Option<&'static mut Capsule> {
    unsafe {
        REG.write().as_mut().and_then(|r| r.capsules.get_mut(&id).map(|c| &mut *(c as *mut _)))
    }
}

pub fn insert_sandbox(id: CapsuleId, sb: Sandbox) {
    if let Some(r) = REG.write().as_mut() {
        r.sandboxes.insert(id, sb);
    }
}

pub fn get_sandbox(id: CapsuleId) -> Option<&'static Sandbox> {
    unsafe { REG.read().as_ref().and_then(|r| r.sandboxes.get(&id).map(|s| &*(s as *const _))) }
}

pub fn get_sandbox_mut(id: CapsuleId) -> Option<&'static mut Sandbox> {
    unsafe {
        REG.write().as_mut().and_then(|r| r.sandboxes.get_mut(&id).map(|s| &mut *(s as *mut _)))
    }
}

pub fn map_pid(pid: u64, id: CapsuleId) {
    if let Some(r) = REG.write().as_mut() {
        r.pid_map.insert(pid, id);
    }
}

pub fn id_by_pid(pid: u64) -> Option<CapsuleId> {
    REG.read().as_ref().and_then(|r| r.pid_map.get(&pid).copied())
}

pub fn sandbox_by_pid(pid: u64) -> Option<&'static Sandbox> {
    id_by_pid(pid).and_then(get_sandbox)
}

pub fn sandbox_by_pid_mut(pid: u64) -> Option<&'static mut Sandbox> {
    id_by_pid(pid).and_then(get_sandbox_mut)
}

pub fn remove(id: CapsuleId) {
    if let Some(r) = REG.write().as_mut() {
        if let Some(c) = r.capsules.remove(&id) {
            if let Some(p) = c.pid {
                r.pid_map.remove(&p);
            }
        }
        r.sandboxes.remove(&id);
    }
}

pub fn set_state(id: CapsuleId, state: CapsuleState) {
    if let Some(c) = get_mut(id) {
        c.state = state;
    }
}

pub fn get_all_ids() -> alloc::vec::Vec<CapsuleId> {
    REG.read().as_ref().map(|r| r.capsules.keys().copied().collect()).unwrap_or_default()
}

pub fn count() -> usize {
    REG.read().as_ref().map(|r| r.capsules.len()).unwrap_or(0)
}
