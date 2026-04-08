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
use crate::capsule::CapsuleId;
use super::stats::{CapsuleStats, GlobalStats};

struct Collector { capsules: BTreeMap<CapsuleId, CapsuleStats>, global: GlobalStats }
static COL: RwLock<Option<Collector>> = RwLock::new(None);

pub fn init() {
    *COL.write() = Some(Collector { capsules: BTreeMap::new(), global: GlobalStats::default() });
    crate::sys::boot_log::ok("METRICS", "Capsule collector ready");
}

pub fn register(id: CapsuleId) {
    let now = crate::time::monotonic_ns();
    if let Some(c) = COL.write().as_mut() {
        c.capsules.insert(id, CapsuleStats::new(now));
        c.global.capsule_started();
    }
}

pub fn unregister(id: CapsuleId, faulted: bool) {
    let now = crate::time::monotonic_ns();
    if let Some(c) = COL.write().as_mut() {
        if let Some(s) = c.capsules.get_mut(&id) { s.finalize(now); }
        c.capsules.remove(&id);
        if faulted { c.global.capsule_faulted(); } else { c.global.capsule_exited(); }
    }
}

pub fn get(id: CapsuleId) -> Option<CapsuleStats> {
    COL.read().as_ref()?.capsules.get(&id).copied()
}

pub fn update<F: FnOnce(&mut CapsuleStats)>(id: CapsuleId, f: F) {
    if let Some(c) = COL.write().as_mut() { if let Some(s) = c.capsules.get_mut(&id) { f(s); } }
}

pub fn global() -> GlobalStats { COL.read().as_ref().map(|c| c.global).unwrap_or_default() }

pub fn record_syscall(id: CapsuleId) { update(id, |s| s.add_syscall()); }
pub fn record_ipc_sent(id: CapsuleId) { update(id, |s| s.add_ipc_sent()); }
pub fn record_ipc_recv(id: CapsuleId) { update(id, |s| s.add_ipc_recv()); }
pub fn record_net_tx(id: CapsuleId, bytes: u64) { update(id, |s| s.add_net_tx(bytes)); }
pub fn record_net_rx(id: CapsuleId, bytes: u64) { update(id, |s| s.add_net_rx(bytes)); }
pub fn record_cpu(id: CapsuleId, ns: u64) { update(id, |s| s.add_cpu(ns)); }
pub fn record_mem(id: CapsuleId, current: u64) { update(id, |s| s.update_mem(current)); }
