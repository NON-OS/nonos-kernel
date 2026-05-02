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

use crate::syscall::dispatch::handle_syscall_dispatch;
use crate::syscall::numbers::SyscallNumber;
use crate::syscall::types::errnos;
use crate::syscall::SyscallResult;

use super::args::SyscallArgs;
use super::capability::Capability;

/// The single entry into syscall dispatch from a per-arch shim.
///
/// Resolves the calling thread's capability against `number`, refuses
/// with `EPERM` if the resolution fails, and otherwise invokes the
/// handler. There is no other path that runs `Capability::resolve`; if a
/// future caller needs to dispatch, they go through this function.
pub fn dispatch(number: SyscallNumber, args: SyscallArgs) -> SyscallResult {
    let _cap = match Capability::resolve(number, &args) {
        Some(c) => c,
        None => return SyscallResult::error(errnos::EPERM),
    };
    invoke(number, args)
}

#[inline]
fn invoke(number: SyscallNumber, args: SyscallArgs) -> SyscallResult {
    let [a0, a1, a2, a3, a4, a5] = args.raw();
    handle_syscall_dispatch(number, a0, a1, a2, a3, a4, a5)
}
