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

//! `MkDebug` handler. A capsule emits one short diagnostic line on the
//! boot serial. The contract layer has already verified the
//! `Capability::Debug` token; this layer only validates the user
//! buffer and writes it through.
//!
//! The line is bounded to `MAX_LEN` bytes after which the syscall
//! returns `-EINVAL`. Empty calls are also rejected. Non-printable
//! bytes are passed through verbatim — the harness greps for exact
//! marker strings, and silently rewriting them would defeat the
//! purpose of having the channel.

use super::errnos::{ERRNO_FAULT, ERRNO_INVAL};

const MAX_LEN: usize = 256;

pub fn sys_mk_debug(user_ptr: u64, len: u64) -> i64 {
    if user_ptr == 0 || len == 0 {
        return ERRNO_INVAL;
    }
    let len = len as usize;
    if len > MAX_LEN {
        return ERRNO_INVAL;
    }
    match crate::usercopy::validate_user_read(user_ptr, len) {
        Ok(()) => {}
        Err(_err) => {
            #[cfg(feature = "nonos-user-entry-proof")]
            super::debug_diag::validate_fail(user_ptr, len, _err);
            return ERRNO_FAULT;
        }
    }
    let mut buf = [0u8; MAX_LEN];
    if crate::usercopy::copy_from_user(user_ptr, &mut buf[..len]).is_err() {
        #[cfg(feature = "nonos-user-entry-proof")]
        super::debug_diag::copy_fail();
        return ERRNO_FAULT;
    }
    crate::sys::serial::print(&buf[..len]);
    len as i64
}
