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

#[no_mangle]
pub unsafe extern "C" fn syscall(
    num: i64,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") num => ret,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") a3,
        in("r10") a4,
        in("r8") a5,
        in("r9") a6,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack)
    );
    if ret < 0 && ret >= -4095 {
        crate::libc::errno::set_errno((-ret) as i32);
        return -1;
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall0(num: i64) -> i64 {
    syscall(num, 0, 0, 0, 0, 0, 0)
}

#[inline(always)]
pub unsafe fn syscall1(num: i64, a1: usize) -> i64 {
    syscall(num, a1, 0, 0, 0, 0, 0)
}

#[inline(always)]
pub unsafe fn syscall2(num: i64, a1: usize, a2: usize) -> i64 {
    syscall(num, a1, a2, 0, 0, 0, 0)
}

#[inline(always)]
pub unsafe fn syscall3(num: i64, a1: usize, a2: usize, a3: usize) -> i64 {
    syscall(num, a1, a2, a3, 0, 0, 0)
}

#[inline(always)]
pub unsafe fn syscall4(num: i64, a1: usize, a2: usize, a3: usize, a4: usize) -> i64 {
    syscall(num, a1, a2, a3, a4, 0, 0)
}

#[inline(always)]
pub unsafe fn syscall5(num: i64, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> i64 {
    syscall(num, a1, a2, a3, a4, a5, 0)
}

#[inline(always)]
pub unsafe fn syscall6(
    num: i64,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> i64 {
    syscall(num, a1, a2, a3, a4, a5, a6)
}
