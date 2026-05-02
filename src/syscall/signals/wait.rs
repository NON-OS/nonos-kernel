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

pub fn handle_rt_sigreturn() -> SyscallResult {
    crate::process::signal::delivery::sigreturn_current()
}

pub fn handle_rt_sigsuspend(mask: u64, sigsetsize: u64) -> SyscallResult {
    let value = crate::process::signal::syscall::sys_rt_sigsuspend(mask, sigsetsize);
    SyscallResult { value, capability_consumed: false, audit_required: value != 0 }
}

pub fn handle_pause() -> SyscallResult {
    let value = crate::process::signal::syscall::sys_pause();
    SyscallResult { value, capability_consumed: false, audit_required: value != 0 }
}
