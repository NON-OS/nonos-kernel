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
use crate::syscall::dispatch::errno;

pub fn handle_io_port_read(port: u16) -> SyscallResult {
    let Some(proc) = crate::process::current_process() else {
        return errno(1);
    };

    if !proc.capability_token().grants(crate::capabilities::Capability::Hardware) {
        return errno(1);
    }

    let value: u8 = unsafe {
        let val: u8;
        core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") val,
            options(nomem, nostack, preserves_flags)
        );
        val
    };

    SyscallResult { value: value as i64, capability_consumed: false, audit_required: true }
}

pub fn handle_io_port_write(port: u16, value: u8) -> SyscallResult {
    let Some(proc) = crate::process::current_process() else {
        return errno(1);
    };

    if !proc.capability_token().grants(crate::capabilities::Capability::Hardware) {
        return errno(1);
    }

    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}
