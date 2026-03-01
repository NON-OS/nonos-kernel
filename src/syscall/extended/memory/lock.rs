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
use crate::syscall::extended::errno;

pub fn handle_mlock(addr: u64, len: u64) -> SyscallResult {
    if addr & 0xFFF != 0 {
        return errno(22);
    }

    let _ = len;
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_mlock2(addr: u64, len: u64, flags: i32) -> SyscallResult {
    let _ = flags;
    handle_mlock(addr, len)
}

pub fn handle_munlock(addr: u64, len: u64) -> SyscallResult {
    if addr & 0xFFF != 0 {
        return errno(22);
    }

    let _ = len;
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_mlockall(flags: i32) -> SyscallResult {
    let _ = flags;
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_munlockall() -> SyscallResult {
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}
