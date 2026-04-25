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

mod register;
mod state;
mod types;
mod unregister;

pub use register::handle_rseq_register;
pub use state::RseqState;
pub use types::{Rseq, RseqCs, RseqFlags};
pub use unregister::handle_rseq_unregister;

use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;

pub fn handle_rseq(rseq_ptr: u64, rseq_len: u32, flags: i32, sig: u32) -> SyscallResult {
    if flags & !0x3 != 0 {
        return errno(22);
    }
    let unregister = flags & 0x1 != 0;
    if unregister {
        unregister::handle_rseq_unregister(rseq_ptr, rseq_len, sig)
    } else {
        register::handle_rseq_register(rseq_ptr, rseq_len, sig)
    }
}
