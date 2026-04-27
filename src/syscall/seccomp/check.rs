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

use super::state::{get_filters, get_mode};
use super::types::*;

pub fn check_syscall(pid: u32, syscall_nr: i32, args: &[u64; 6]) -> SeccompResult {
    let mode = get_mode(pid);
    match mode {
        SECCOMP_MODE_DISABLED => SeccompResult::Allow,
        SECCOMP_MODE_STRICT => check_strict(syscall_nr),
        SECCOMP_MODE_FILTER => check_filters(pid, syscall_nr, args),
        _ => SeccompResult::Allow,
    }
}

fn check_strict(syscall_nr: i32) -> SeccompResult {
    match syscall_nr {
        0 | 1 | 3 | 60 | 231 => SeccompResult::Allow,
        _ => SeccompResult::Kill,
    }
}

fn check_filters(pid: u32, syscall_nr: i32, args: &[u64; 6]) -> SeccompResult {
    let filters = get_filters(pid);
    if filters.is_empty() {
        return SeccompResult::Allow;
    }
    let data =
        SeccompData { nr: syscall_nr, arch: 0xC000003E, instruction_pointer: 0, args: *args };
    for filter in &filters {
        let result = filter.run(&data);
        let action = result & SECCOMP_RET_ACTION_FULL;
        match action {
            SECCOMP_RET_ALLOW => continue,
            SECCOMP_RET_KILL_PROCESS | SECCOMP_RET_KILL_THREAD => return SeccompResult::Kill,
            SECCOMP_RET_TRAP => return SeccompResult::Trap,
            SECCOMP_RET_ERRNO => return SeccompResult::Errno((result & SECCOMP_RET_DATA) as i32),
            SECCOMP_RET_TRACE => return SeccompResult::Trace((result & SECCOMP_RET_DATA) as u16),
            SECCOMP_RET_LOG => return SeccompResult::Log,
            _ => continue,
        }
    }
    SeccompResult::Allow
}

#[derive(Debug, Clone, Copy)]
pub enum SeccompResult {
    Allow,
    Kill,
    Trap,
    Errno(i32),
    Trace(u16),
    Log,
}

pub fn is_allowed(pid: u32, syscall_nr: i32, args: &[u64; 6]) -> bool {
    matches!(check_syscall(pid, syscall_nr, args), SeccompResult::Allow | SeccompResult::Log)
}
