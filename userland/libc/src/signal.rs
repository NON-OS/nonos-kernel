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

use crate::syscall::N_RT_SIGRETURN;

/// Permanent userland-ABI return point for signal handlers. The kernel
/// sets the saved RIP of a signal frame to the address of this symbol;
/// when a handler `ret`s, control reaches here and a single SYSCALL
/// hands back to the kernel's sigreturn implementation, which pops the
/// sigframe and resumes the pre-signal context.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __nonos_rt_sigreturn() -> ! {
    core::arch::naked_asm!(
        "mov rax, {n}",
        "syscall",
        "ud2",
        n = const N_RT_SIGRETURN,
    );
}
