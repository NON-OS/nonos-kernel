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
use super::types::IoEvent;
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::copy_to_user;

pub fn handle_io_getevents(
    ctx_id: u64,
    min_nr: i64,
    nr: i64,
    events_ptr: u64,
    _timeout: u64,
) -> SyscallResult {
    if events_ptr == 0 && nr > 0 {
        return errno(14);
    }
    match AioContext::getevents(ctx_id, min_nr, nr) {
        Ok(events) => {
            let event_size = core::mem::size_of::<IoEvent>();
            for (i, event) in events.iter().enumerate() {
                let ptr = events_ptr + (i * event_size) as u64;
                let bytes = unsafe {
                    core::slice::from_raw_parts(event as *const IoEvent as *const u8, event_size)
                };
                if copy_to_user(ptr, bytes).is_err() {
                    return errno(14);
                }
            }
            SyscallResult {
                value: events.len() as i64,
                capability_consumed: false,
                audit_required: false,
            }
        }
        Err(e) => errno(e),
    }
}
