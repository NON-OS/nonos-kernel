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

use super::context::AioContext;
use super::types::Iocb;
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::{read_user_value, write_user_value};

pub fn handle_io_cancel(ctx_id: u64, iocb_ptr: u64, result_ptr: u64) -> SyscallResult {
    if ctx_id == 0 || iocb_ptr == 0 {
        return errno(22);
    }
    let iocb: Iocb = match read_user_value(iocb_ptr) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    match AioContext::cancel(ctx_id, iocb.aio_data) {
        Ok(event) => {
            if result_ptr != 0 {
                if write_user_value(result_ptr, &event).is_err() {
                    return errno(14);
                }
            }
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        Err(e) => errno(e),
    }
}

pub fn cancel_all_for_context(ctx_id: u64) -> usize {
    AioContext::cancel_all(ctx_id).unwrap_or(0)
}

pub fn cancel_by_fd(ctx_id: u64, fd: i32) -> usize {
    AioContext::cancel_by_fd(ctx_id, fd).unwrap_or(0)
}

pub fn is_cancellable(ctx_id: u64, data: u64) -> bool {
    AioContext::has_pending(ctx_id, data)
}
