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

pub fn handle_kill(pid: i64, sig: u64) -> SyscallResult {
    let value = crate::process::signal::syscall::sys_kill(pid, sig);
    SyscallResult { value, capability_consumed: false, audit_required: true }
}

pub fn handle_tgkill(tgid: u64, tid: u64, sig: u64) -> SyscallResult {
    let value = crate::process::signal::syscall::sys_tgkill(tgid, tid, sig);
    SyscallResult { value, capability_consumed: false, audit_required: value != 0 }
}

pub fn handle_tkill(tid: u64, sig: u64) -> SyscallResult {
    let value = crate::process::signal::syscall::sys_tkill(tid, sig);
    SyscallResult { value, capability_consumed: false, audit_required: value != 0 }
}

pub fn handle_rt_sigqueueinfo(pid: u64, sig: u64, info: u64) -> SyscallResult {
    let value = crate::process::signal::syscall::sys_rt_sigqueueinfo(pid, sig, info);
    SyscallResult { value, capability_consumed: false, audit_required: value != 0 }
}
