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
use super::types::MqAttr;
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_to_user, read_user_value};

pub fn handle_mq_getsetattr(mqdes: i32, new_attr_ptr: u64, old_attr_ptr: u64) -> SyscallResult {
    let old_attr = match MessageQueue::getattr(mqdes) {
        Ok(a) => a,
        Err(e) => return errno(e),
    };
    if old_attr_ptr != 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &old_attr as *const MqAttr as *const u8,
                core::mem::size_of::<MqAttr>(),
            )
        };
        if copy_to_user(old_attr_ptr, bytes).is_err() {
            return errno(14);
        }
    }
    if new_attr_ptr != 0 {
        let new_attr: MqAttr = match read_user_value(new_attr_ptr) {
            Ok(a) => a,
            Err(_) => return errno(14),
        };
        if let Err(e) = MessageQueue::setattr(mqdes, &new_attr) {
            return errno(e);
        }
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}
