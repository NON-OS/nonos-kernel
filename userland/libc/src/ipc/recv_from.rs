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

use crate::syscall::{call_raw, N_MK_IPC_RECV_FROM};

// Dequeue one message and write the sender pid to `sender_pid_out`
// (if non-null). Same blocking + timeout semantics as `mk_ipc_recv`.
#[no_mangle]
pub extern "C" fn mk_ipc_recv_from(
    endpoint: u64,
    buf: *mut u8,
    len: usize,
    timeout_ms: u64,
    sender_pid_out: *mut u32,
) -> i64 {
    call_raw(
        N_MK_IPC_RECV_FROM,
        [endpoint, buf as u64, len as u64, timeout_ms, sender_pid_out as u64, 0],
    )
}
