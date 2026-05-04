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

// Admin bit. Required to call `sys_cap_grant`/`sys_cap_revoke` and
// kept consistent with `INIT_CAPABILITIES` below.
const CAP_ADMIN: u64 = 1u64 << 63;

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
    // Caller must (1) hold CAP_ADMIN and (2) hold every bit it is trying
    // to grant. The subset check is what stops an admin from manufacturing
    // authority it never received itself. Internal kernel grants run
    // through `grant_caps_internal` and bypass both checks by design.
    let mut table = CAP_TABLE.lock();
    let caller_caps = table.iter().find(|e| e.pid == caller).map(|e| e.caps).unwrap_or(0);
    if caller_caps & CAP_ADMIN == 0 || caller_caps & caps != caps {
        return E_PERM;
    }
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
    // Fail-closed: a pid not in the table has no caps. Init does not get
    // admin implicitly; `init_cap_for_init` is the only on-ramp.
    table.iter().find(|e| e.pid == pid).map(|e| e.caps & CAP_ADMIN != 0).unwrap_or(false)
}

/// Capability bits for init (PID 1). Minimal set: admin so init can mint
/// children's caps, plus the families it actually needs at boot.
const INIT_CAPABILITIES: u64 = {
    const CAP_PROCESS: u64 = 1 << 0;
    const CAP_MEMORY: u64 = 1 << 1;
    const CAP_IPC: u64 = 1 << 2;
    const CAP_FILESYSTEM: u64 = 1 << 3;
    const CAP_NETWORK: u64 = 1 << 4;
    const CAP_DEVICE: u64 = 1 << 5;
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
