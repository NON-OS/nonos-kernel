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

use crate::capabilities::Capability;
use crate::syscall::SyscallResult;
use crate::syscall::dispatch::{errno, require_capability, set_audit_verbose};

pub fn handle_debug_log(msg_ptr: u64, len: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Debug) {
        return e;
    }

    if msg_ptr == 0 || len == 0 || len > 4096 {
        return errno(22);
    }

    let message = unsafe {
        core::slice::from_raw_parts(msg_ptr as *const u8, len as usize)
    };

    if let Ok(msg) = core::str::from_utf8(message) {
        crate::log::debug!("[USER] {}", msg);
    } else {
        crate::log::debug!("[USER] <binary data {} bytes>", len);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_debug_trace(flags: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Debug) {
        return e;
    }

    match flags {
        0 => {
            set_audit_verbose(false);
            crate::log::debug!("Debug tracing disabled");
        }
        1 => {
            set_audit_verbose(true);
            crate::log::debug!("Syscall tracing enabled");
        }
        2 => {
            crate::log::debug!("Memory tracing enabled");
        }
        _ => return errno(22),
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}
