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
use crate::usercopy::read_user_value;

pub fn handle_mq_open(name_ptr: u64, flags: i32, mode: u32, attr_ptr: u64) -> SyscallResult {
    if name_ptr == 0 {
        return errno(14);
    }
    let name = match crate::syscall::dispatch::util::parse_string_from_user(name_ptr, 255) {
        Ok(n) => n,
        Err(_) => return errno(14),
    };
    if !name.starts_with('/') || name.len() < 2 {
        return errno(22);
    }
    let attr = if attr_ptr != 0 && (flags & 0o100) != 0 {
        match read_user_value::<MqAttr>(attr_ptr) {
            Ok(a) => Some(a),
            Err(_) => return errno(14),
        }
    } else {
        None
    };
    match MessageQueue::open(&name, flags, mode, attr) {
        Ok(fd) => {
            SyscallResult { value: fd as i64, capability_consumed: false, audit_required: true }
        }
        Err(e) => errno(e),
    }
}
