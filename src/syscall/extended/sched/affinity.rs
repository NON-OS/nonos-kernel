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

use super::util::{can_modify_process, ok, resolve_pid};
use crate::process::scheduler as policy;
use crate::syscall::extended::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_from_user, copy_to_user, read_user_value, write_user_value};

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

    let cpu_mask = if cpusetsize >= 8 {
        match read_user_value::<u64>(mask) {
            Ok(v) => v,
            Err(_) => return errno(14),
        }
    } else {
        let mut bytes = [0u8; 8];
        let copy_len = (cpusetsize as usize).min(8);
        if copy_from_user(mask, &mut bytes[..copy_len]).is_err() {
            return errno(14);
        }
        u64::from_ne_bytes(bytes)
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

    if cpusetsize >= 8 {
        if write_user_value(mask, &cpu_mask).is_err() {
            return errno(14);
        }
    } else {
        let bytes = cpu_mask.to_ne_bytes();
        let copy_len = (cpusetsize as usize).min(8);
        if copy_to_user(mask, &bytes[..copy_len]).is_err() {
            return errno(14);
        }
    }

    let bytes = core::cmp::min(cpusetsize, 8);
    ok(bytes as i64)
}
