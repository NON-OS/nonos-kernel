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
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::write_user_value;

pub fn handle_io_setup(nr_events: u32, ctx_idp: u64) -> SyscallResult {
    if ctx_idp == 0 {
        return errno(14);
    }
    match AioContext::create(nr_events) {
        Ok(ctx_id) => {
            if write_user_value(ctx_idp, &ctx_id).is_err() {
                let _ = AioContext::destroy(ctx_id);
                return errno(14);
            }
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        Err(e) => errno(e),
    }
}
