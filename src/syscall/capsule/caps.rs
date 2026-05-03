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

use crate::capsule::{self, CapsuleId};
use crate::process::current_pid;

pub const SYS_CAPSULE_HAS_CAP: usize = 520;
pub const SYS_CAPSULE_USE_CAP: usize = 521;
pub const SYS_CAPSULE_GET_CAPS: usize = 522;

pub fn sys_capsule_has_cap(cap: u64) -> i64 {
    let pid = current_pid();
    match capsule::registry::sandbox_by_pid(pid) {
        Some(sb) => {
            if sb.has_cap(cap) {
                1
            } else {
                0
            }
        }
        None => -1,
    }
}

pub fn sys_capsule_use_cap(cap: u64) -> i64 {
    let pid = current_pid();
    match capsule::registry::sandbox_by_pid_mut(pid) {
        Some(sb) => match sb.use_cap(cap) {
            Ok(()) => 0,
            Err(_) => -1,
        },
        None => -1,
    }
}

pub fn sys_capsule_get_caps() -> i64 {
    let pid = current_pid();
    match capsule::registry::sandbox_by_pid(pid) {
        Some(sb) => sb.caps() as i64,
        None => -1,
    }
}

pub fn sys_capsule_alloc_mem(size: u64) -> i64 {
    let pid = current_pid();
    match capsule::registry::sandbox_by_pid_mut(pid) {
        Some(sb) => match sb.alloc_mem(size) {
            Ok(()) => 0,
            Err(_) => -1,
        },
        None => -1,
    }
}

pub fn sys_capsule_free_mem(size: u64) -> i64 {
    let pid = current_pid();
    if let Some(sb) = capsule::registry::sandbox_by_pid_mut(pid) {
        sb.free_mem(size);
    }
    0
}
