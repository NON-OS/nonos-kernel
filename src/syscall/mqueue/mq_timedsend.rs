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

extern crate alloc;

use super::queue::MessageQueue;
use super::types::MQ_PRIO_MAX;
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::copy_from_user;
use alloc::vec;

pub fn handle_mq_timedsend(
    mqdes: i32,
    msg_ptr: u64,
    msg_len: u64,
    msg_prio: u32,
    _timeout: u64,
) -> SyscallResult {
    if msg_ptr == 0 && msg_len > 0 {
        return errno(14);
    }
    if msg_prio >= MQ_PRIO_MAX {
        return errno(22);
    }
    let mut msg = vec![0u8; msg_len as usize];
    if msg_len > 0 && copy_from_user(msg_ptr, &mut msg).is_err() {
        return errno(14);
    }
    match MessageQueue::send(mqdes, msg, msg_prio) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(e) => errno(e),
    }
}
