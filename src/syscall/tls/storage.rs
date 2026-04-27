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

use super::types::{TlsDescriptor, GDT_ENTRY_TLS_ENTRIES, GDT_ENTRY_TLS_MIN};
use alloc::collections::BTreeMap;
use spin::Mutex;

#[derive(Clone, Copy, Default)]
pub struct ThreadTlsState {
    pub fs_base: u64,
    pub gs_base: u64,
    pub kernel_gs_base: u64,
    pub tls_entries: [TlsDescriptor; GDT_ENTRY_TLS_ENTRIES],
    pub cpuid_enabled: bool,
}

static TLS_STATE: Mutex<BTreeMap<u64, ThreadTlsState>> = Mutex::new(BTreeMap::new());

pub fn get_or_create_state(tid: u64) -> ThreadTlsState {
    let mut map = TLS_STATE.lock();
    map.entry(tid)
        .or_insert_with(|| ThreadTlsState { cpuid_enabled: true, ..Default::default() })
        .clone()
}

pub fn set_fs_base(tid: u64, base: u64) {
    TLS_STATE.lock().entry(tid).or_default().fs_base = base;
}

pub fn get_fs_base(tid: u64) -> u64 {
    TLS_STATE.lock().get(&tid).map(|s| s.fs_base).unwrap_or(0)
}

pub fn set_gs_base(tid: u64, base: u64) {
    TLS_STATE.lock().entry(tid).or_default().gs_base = base;
}

pub fn get_gs_base(tid: u64) -> u64 {
    TLS_STATE.lock().get(&tid).map(|s| s.gs_base).unwrap_or(0)
}

pub fn set_kernel_gs_base(tid: u64, base: u64) {
    TLS_STATE.lock().entry(tid).or_default().kernel_gs_base = base;
}

pub fn get_kernel_gs_base(tid: u64) -> u64 {
    TLS_STATE.lock().get(&tid).map(|s| s.kernel_gs_base).unwrap_or(0)
}

pub fn set_tls_entry(tid: u64, index: usize, desc: TlsDescriptor) -> Result<(), i32> {
    if index < GDT_ENTRY_TLS_MIN || index >= GDT_ENTRY_TLS_MIN + GDT_ENTRY_TLS_ENTRIES {
        return Err(22);
    }
    let slot = index - GDT_ENTRY_TLS_MIN;
    TLS_STATE.lock().entry(tid).or_default().tls_entries[slot] = desc;
    Ok(())
}

pub fn get_tls_entry(tid: u64, index: usize) -> Result<TlsDescriptor, i32> {
    if index < GDT_ENTRY_TLS_MIN || index >= GDT_ENTRY_TLS_MIN + GDT_ENTRY_TLS_ENTRIES {
        return Err(22);
    }
    let slot = index - GDT_ENTRY_TLS_MIN;
    Ok(TLS_STATE.lock().get(&tid).map(|s| s.tls_entries[slot]).unwrap_or_default())
}

pub fn find_free_tls_slot(tid: u64) -> Option<usize> {
    let map = TLS_STATE.lock();
    let state = map.get(&tid);
    for i in 0..GDT_ENTRY_TLS_ENTRIES {
        if state.map(|s| !s.tls_entries[i].valid).unwrap_or(true) {
            return Some(GDT_ENTRY_TLS_MIN + i);
        }
    }
    None
}

pub fn clone_tls_state(parent_tid: u64, child_tid: u64) {
    let mut map = TLS_STATE.lock();
    if let Some(parent_state) = map.get(&parent_tid).copied() {
        map.insert(child_tid, parent_state);
    }
}

pub fn clear_tls_state(tid: u64) {
    TLS_STATE.lock().remove(&tid);
}

pub fn set_cpuid_enabled(tid: u64, enabled: bool) {
    TLS_STATE.lock().entry(tid).or_default().cpuid_enabled = enabled;
}

pub fn get_cpuid_enabled(tid: u64) -> bool {
    TLS_STATE.lock().get(&tid).map(|s| s.cpuid_enabled).unwrap_or(true)
}
