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

use crate::syscall::SyscallResult;
use crate::process::scheduler as policy;
use crate::syscall::extended::errno;
use super::util::{resolve_pid, can_modify_process, ok};

pub fn handle_sched_setaffinity(pid: i32, cpusetsize: u64, mask: u64) -> SyscallResult {
    if mask == 0 {
        return errno(14);
    }

    if cpusetsize == 0 {
        return errno(22);
    }

    let target_pid = match resolve_pid(pid) {
        Some(p) => p,
        None => return errno(3),
    };

    if !can_modify_process(target_pid) {
        return errno(1);
    }

    let cpu_mask = unsafe {
        if cpusetsize >= 8 {
            core::ptr::read(mask as *const u64)
        } else {
            let mut m = 0u64;
            let bytes = core::slice::from_raw_parts(mask as *const u8, cpusetsize as usize);
            for (i, &b) in bytes.iter().enumerate() {
                m |= (b as u64) << (i * 8);
            }
            m
        }
    };

    if let Err(_) = policy::set_affinity(target_pid, cpu_mask) {
        return errno(22);
    }

    ok(0)
}

pub fn handle_sched_getaffinity(pid: i32, cpusetsize: u64, mask: u64) -> SyscallResult {
    if cpusetsize == 0 || mask == 0 {
        return errno(14);
    }

    let target_pid = match resolve_pid(pid) {
        Some(p) => p,
        None => return errno(3),
    };

    let cpu_mask = policy::get_affinity(target_pid);

    unsafe {
        if cpusetsize >= 8 {
            core::ptr::write(mask as *mut u64, cpu_mask);
        } else {
            let bytes = core::slice::from_raw_parts_mut(mask as *mut u8, cpusetsize as usize);
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = ((cpu_mask >> (i * 8)) & 0xFF) as u8;
            }
        }
    }

    let bytes = core::cmp::min(cpusetsize, 8);
    ok(bytes as i64)
}
