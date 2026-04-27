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

use super::state::RseqState;
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;

pub fn handle_rseq_unregister(rseq_ptr: u64, rseq_len: u32, sig: u32) -> SyscallResult {
    if rseq_ptr == 0 {
        return errno(14);
    }
    let pid = crate::process::current_pid().unwrap_or(1) as u64;
    match RseqState::unregister(pid, rseq_ptr, rseq_len, sig) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(e) => errno(e),
    }
}
