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

//! NØNOS-native debug trace channel. The capsule emits one short
//! diagnostic line on the boot serial. The kernel handler is gated
//! by `Capability::Debug` and bounded to 256 bytes per call. There
//! is no fd, no POSIX semantics, and no relation to Linux `write`.

use crate::syscall::{call_raw, N_MK_DEBUG};

pub fn mk_debug(buf: *const u8, len: usize) -> i64 {
    if buf.is_null() || len == 0 {
        return -22;
    }
    call_raw(N_MK_DEBUG, [buf as u64, len as u64, 0, 0, 0, 0])
}
