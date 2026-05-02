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

use core::arch::asm;

/// x86_64 SYSCALL trampoline. Issues `syscall` with the System V
/// register layout the NONOS per-arch shim expects:
///
///   rax = number, rdi = a1, rsi = a2, rdx = a3,
///   r10 = a4    (rcx is clobbered by SYSCALL itself),
///   r8  = a5,   r9  = a6
///
/// The kernel returns in rax. SYSCALL clobbers rcx (return RIP) and
/// r11 (return RFLAGS); we mark those.
///
/// # Safety
/// This is the leaf at which user-mode hands control to the kernel.
/// The caller is responsible for argument meaning. Bad pointers do not
/// produce undefined behavior here; the kernel returns `-EFAULT`.
#[inline]
pub(super) unsafe fn raw(num: i64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i64 {
    let ret: i64;
    asm!(
        "syscall",
        inlateout("rax") num => ret,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") a3,
        in("r10") a4,
        in("r8")  a5,
        in("r9")  a6,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack),
    );
    ret
}
