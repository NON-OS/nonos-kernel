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

use crate::process::PROCESS_TABLE;

pub fn check_process_access(pid: i32) -> Result<u32, i32> {
    if pid <= 0 {
        return Err(-22);
    }
    let target_pid = pid as u32;
    let current = crate::process::current_pid().ok_or(-3i32)?;
    if target_pid != current {
        if PROCESS_TABLE.find_by_pid(target_pid).is_none() {
            return Err(-3);
        }
        if !has_ptrace_permission(current, target_pid) {
            return Err(-1);
        }
    }
    Ok(target_pid)
}

pub fn has_ptrace_permission(source_pid: u32, target_pid: u32) -> bool {
    if source_pid == target_pid {
        return true;
    }
    if source_pid == 0 || source_pid == 1 {
        return true;
    }
    let source = match PROCESS_TABLE.find_by_pid(source_pid) {
        Some(p) => p,
        None => return false,
    };
    let target = match PROCESS_TABLE.find_by_pid(target_pid) {
        Some(p) => p,
        None => return false,
    };
    if source.parent_pid() == target_pid {
        return true;
    }
    if target.parent_pid() == source_pid {
        return true;
    }
    if source.session_id() == target.session_id() {
        return true;
    }
    false
}

pub fn is_same_address_space(target_pid: u32) -> bool {
    let current = crate::process::current_pid().unwrap_or(0);
    target_pid == current
}

pub fn get_target_cr3(target_pid: u32) -> Option<u64> {
    crate::memory::paging::get_process_cr3(target_pid)
}

pub fn validate_remote_range(pid: u32, addr: usize, len: usize) -> Result<(), i32> {
    if len == 0 {
        return Ok(());
    }
    if addr == 0 {
        return Err(-14);
    }
    if addr.checked_add(len).is_none() {
        return Err(-14);
    }
    let pcb = PROCESS_TABLE.find_by_pid(pid).ok_or(-3i32)?;
    let mem = pcb.memory.lock();
    for vma in mem.vmas.iter() {
        let vma_start = vma.start.as_u64() as usize;
        let vma_end = vma.end.as_u64() as usize;
        if addr >= vma_start && addr + len <= vma_end {
            return Ok(());
        }
    }
    Err(-14)
}
