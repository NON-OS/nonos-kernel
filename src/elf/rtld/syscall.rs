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

// rtld-internal bridge into the syscall entry contract. The in-kernel
// dynamic linker reads ELF objects and sets up TLS via the file/fs and
// process-sched syscall families, so the calling loader thread must
// hold a capability token covering those families. If the contract
// returns EPERM here, the loader is running without the right token
// and the fix is in process setup, not in this module.

use crate::syscall::contract::{dispatch, SyscallArgs};
use crate::syscall::numbers::SyscallNumber;

#[inline]
pub(super) fn call(num: SyscallNumber, args: [u64; 6]) -> i64 {
    dispatch(num, SyscallArgs::new(args)).value
}
