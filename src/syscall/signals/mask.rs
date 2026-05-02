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

pub fn handle_rt_sigprocmask(how: u64, set: u64, oldset: u64, sigsetsize: u64) -> SyscallResult {
    let value = crate::process::signal::syscall::sys_rt_sigprocmask(how, set, oldset, sigsetsize);
    SyscallResult { value, capability_consumed: false, audit_required: value != 0 }
}

pub fn handle_rt_sigpending(set: u64, sigsetsize: u64) -> SyscallResult {
    let value = crate::process::signal::syscall::sys_rt_sigpending(set, sigsetsize);
    SyscallResult { value, capability_consumed: false, audit_required: value != 0 }
}
