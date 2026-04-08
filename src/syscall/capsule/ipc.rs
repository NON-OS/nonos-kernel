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

use crate::capsule::{self, CapsuleId, metrics};
use crate::ipc::capsule as cipc;
use crate::process::current_pid;

pub const SYS_CAPSULE_IPC_SEND: usize = 530;
pub const SYS_CAPSULE_IPC_RECV: usize = 531;
pub const SYS_CAPSULE_IPC_PEEK: usize = 532;
pub const SYS_CAPSULE_IPC_PENDING: usize = 533;

pub fn sys_capsule_ipc_send(dst: CapsuleId, data_ptr: usize, data_len: usize) -> i64 {
    let pid = current_pid();
    let src = match capsule::registry::id_by_pid(pid) { Some(id) => id, None => return -1 };
    let data = match crate::usercopy::copy_from_user(data_ptr, data_len) { Ok(d) => d, Err(_) => return -1 };
    match cipc::send_data(src, dst, data) {
        Ok(id) => { metrics::collector::record_ipc_sent(src); id as i64 }
        Err(_) => -1,
    }
}

pub fn sys_capsule_ipc_recv(buf_ptr: usize, buf_len: usize) -> i64 {
    let pid = current_pid();
    let id = match capsule::registry::id_by_pid(pid) { Some(id) => id, None => return -1 };
    let msg = match cipc::recv(id) { Ok(m) => m, Err(_) => return -1 };
    let len = msg.payload.len().min(buf_len);
    if crate::usercopy::copy_to_user(buf_ptr, &msg.payload[..len]).is_err() { return -1; }
    metrics::collector::record_ipc_recv(id);
    len as i64
}

pub fn sys_capsule_ipc_peek(buf_ptr: usize, buf_len: usize) -> i64 {
    let pid = current_pid();
    let id = match capsule::registry::id_by_pid(pid) { Some(id) => id, None => return -1 };
    let msg = match cipc::peek(id) { Some(m) => m, None => return 0 };
    let len = msg.payload.len().min(buf_len);
    if crate::usercopy::copy_to_user(buf_ptr, &msg.payload[..len]).is_err() { return -1; }
    len as i64
}

pub fn sys_capsule_ipc_pending() -> i64 {
    let pid = current_pid();
    match capsule::registry::id_by_pid(pid) {
        Some(id) => cipc::pending(id) as i64,
        None => -1,
    }
}
