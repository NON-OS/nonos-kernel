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

use crate::process::current_pid;
use alloc::vec::Vec;
use spin::Mutex;

const E_PERM: i64 = -1;

struct CapEntry {
    pid: u32,
    caps: u64,
}

static CAP_TABLE: Mutex<Vec<CapEntry>> = Mutex::new(Vec::new());

pub fn sys_cap_grant(target_pid: u32, caps: u64) -> i64 {
    let caller = match current_pid() {
        Some(p) => p,
        None => return E_PERM,
    };
    if !has_admin_cap(caller) {
        return E_PERM;
    }
    let mut table = CAP_TABLE.lock();
    if let Some(entry) = table.iter_mut().find(|e| e.pid == target_pid) {
        entry.caps |= caps;
    } else {
        table.push(CapEntry { pid: target_pid, caps });
    }
    0
}

pub fn sys_cap_revoke(target_pid: u32, caps: u64) -> i64 {
    let caller = match current_pid() {
        Some(p) => p,
        None => return E_PERM,
    };
    if !has_admin_cap(caller) {
        return E_PERM;
    }
    let mut table = CAP_TABLE.lock();
    if let Some(entry) = table.iter_mut().find(|e| e.pid == target_pid) {
        entry.caps &= !caps;
    }
    0
}

pub fn sys_cap_check(target_pid: u32, caps: u64) -> i64 {
    let table = CAP_TABLE.lock();
    if let Some(entry) = table.iter().find(|e| e.pid == target_pid) {
        if (entry.caps & caps) == caps {
            1
        } else {
            0
        }
    } else {
        0
    }
}

fn has_admin_cap(pid: u32) -> bool {
    let table = CAP_TABLE.lock();
    // SECURITY FIX: Fail-closed authorization - if process not in table, deny access
    // Do NOT grant admin to PID 1 by default - it must be explicitly granted via init_cap_for_init
    table.iter().find(|e| e.pid == pid).map(|e| e.caps & (1 << 63) != 0).unwrap_or(false)
}

/// Capability bits for init process (PID 1) - minimal necessary capabilities
const INIT_CAPABILITIES: u64 = {
    const CAP_ADMIN: u64 = 1 << 63; // Required for granting caps to child processes
    const CAP_PROCESS: u64 = 1 << 0; // Process management
    const CAP_MEMORY: u64 = 1 << 1; // Memory management
    const CAP_IPC: u64 = 1 << 2; // IPC operations
    const CAP_FILESYSTEM: u64 = 1 << 3; // Filesystem access
    const CAP_NETWORK: u64 = 1 << 4; // Network access
    const CAP_DEVICE: u64 = 1 << 5; // Device access
    CAP_ADMIN | CAP_PROCESS | CAP_MEMORY | CAP_IPC | CAP_FILESYSTEM | CAP_NETWORK | CAP_DEVICE
};

pub fn init_cap_for_init() {
    let mut table = CAP_TABLE.lock();
    // Grant init process (PID 1) the minimal required capabilities, not u64::MAX
    // This is a security improvement - init should only have what it needs
    table.push(CapEntry { pid: 1, caps: INIT_CAPABILITIES });

    // Log capability initialization for audit
    crate::log::info!("[CAPS] Init process (PID 1) granted capabilities: {:#x}", INIT_CAPABILITIES);
}

pub fn grant_caps_internal(pid: u32, caps: u64) {
    let mut table = CAP_TABLE.lock();
    if let Some(entry) = table.iter_mut().find(|e| e.pid == pid) {
        entry.caps |= caps;
    } else {
        table.push(CapEntry { pid, caps });
    }
}

pub fn check_caps_internal(pid: u32, required: u64) -> bool {
    let table = CAP_TABLE.lock();
    table.iter().find(|e| e.pid == pid).map(|e| (e.caps & required) == required).unwrap_or(false)
}
