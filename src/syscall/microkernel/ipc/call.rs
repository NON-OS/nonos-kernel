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

use super::recv::sys_ipc_recv;
use super::send::sys_ipc_send;

// Send-then-recv. The reply lands in the caller's per-process inbox,
// not on `endpoint.<ep>`; recv with endpoint = 0 to read it. Using
// `ep` here would route through the registry-owned named inbox and
// deny because the caller doesn't own it.
pub fn sys_ipc_call(ep: u64, req: u64, req_len: usize, resp: u64, resp_len: usize) -> i64 {
    let send_result = sys_ipc_send(ep, req, req_len);
    if send_result < 0 {
        return send_result;
    }
    sys_ipc_recv(0, resp, resp_len, 5000)
}
