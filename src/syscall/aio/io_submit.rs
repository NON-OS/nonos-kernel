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

use super::context::AioContext;
use super::types::Iocb;
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::read_user_value;
use alloc::vec::Vec;

pub fn handle_io_submit(ctx_id: u64, nr: i64, iocbpp: u64) -> SyscallResult {
    if nr < 0 || iocbpp == 0 {
        return errno(22);
    }
    if nr == 0 {
        return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
    }
    let mut iocbs = Vec::with_capacity(nr as usize);
    for i in 0..nr as usize {
        let ptr_addr = iocbpp + (i * 8) as u64;
        let iocb_ptr: u64 = match read_user_value(ptr_addr) {
            Ok(v) => v,
            Err(_) => return errno(14),
        };
        let iocb: Iocb = match read_user_value(iocb_ptr) {
            Ok(v) => v,
            Err(_) => return errno(14),
        };
        iocbs.push(iocb);
    }
    match AioContext::submit(ctx_id, iocbs) {
        Ok(count) => {
            SyscallResult { value: count as i64, capability_consumed: false, audit_required: false }
        }
        Err(e) => errno(e),
    }
}
