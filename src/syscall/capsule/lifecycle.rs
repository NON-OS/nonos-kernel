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

use crate::capsule::{self, lifecycle, CapsuleId};

pub const SYS_CAPSULE_START: usize = 550;
pub const SYS_CAPSULE_SUSPEND: usize = 551;
pub const SYS_CAPSULE_RESUME: usize = 552;
pub const SYS_CAPSULE_TERMINATE: usize = 553;

pub fn sys_capsule_start(id: CapsuleId) -> i64 {
    match lifecycle::manager::start(id) {
        Ok(pid) => pid as i64,
        Err(_) => -1,
    }
}

pub fn sys_capsule_suspend(id: CapsuleId) -> i64 {
    match lifecycle::manager::suspend(id) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

pub fn sys_capsule_resume(id: CapsuleId) -> i64 {
    match lifecycle::manager::resume(id) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

pub fn sys_capsule_terminate(id: CapsuleId, code: i32) -> i64 {
    match lifecycle::manager::terminate(id, code) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

pub fn sys_capsule_exit(code: i32) -> i64 {
    let pid = crate::process::current_pid();
    let id = match capsule::registry::id_by_pid(pid) {
        Some(id) => id,
        None => return -1,
    };
    let _ = lifecycle::manager::terminate(id, code);
    0
}
