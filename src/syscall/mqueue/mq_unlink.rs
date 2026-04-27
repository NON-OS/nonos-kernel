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

pub fn handle_mq_unlink(name_ptr: u64) -> SyscallResult {
    if name_ptr == 0 {
        return errno(14);
    }
    let name = match crate::syscall::dispatch::util::parse_string_from_user(name_ptr, 255) {
        Ok(n) => n,
        Err(_) => return errno(14),
    };
    match MessageQueue::unlink(&name) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(e) => errno(e),
    }
}
