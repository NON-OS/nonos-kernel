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

use super::queue::MessageQueue;
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_to_user, write_user_value};

pub fn handle_mq_timedreceive(
    mqdes: i32,
    msg_ptr: u64,
    msg_len: u64,
    prio_ptr: u64,
    _timeout: u64,
) -> SyscallResult {
    if msg_ptr == 0 {
        return errno(14);
    }
    match MessageQueue::receive(mqdes) {
        Ok((msg, prio)) => {
            if msg.len() > msg_len as usize {
                return errno(90);
            }
            if copy_to_user(msg_ptr, &msg).is_err() {
                return errno(14);
            }
            if prio_ptr != 0 && write_user_value(prio_ptr, &prio).is_err() {
                return errno(14);
            }
            SyscallResult {
                value: msg.len() as i64,
                capability_consumed: false,
                audit_required: false,
            }
        }
        Err(e) => errno(e),
    }
}
