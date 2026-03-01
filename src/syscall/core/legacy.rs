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

#[inline]
pub fn legacy_handle_syscall2(id: u64, a0: u64, a1: u64) -> u64 {
    crate::syscall::handle_syscall(id, a0, a1, 0, 0, 0, 0)
}

#[inline]
pub fn legacy_handle_syscall3(id: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    crate::syscall::handle_syscall(id, a0, a1, a2, 0, 0, 0)
}

#[inline]
pub fn legacy_handle_syscall4(id: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    crate::syscall::handle_syscall(id, a0, a1, a2, a3, 0, 0)
}

#[inline]
pub fn legacy_handle_syscall5(id: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    crate::syscall::handle_syscall(id, a0, a1, a2, a3, a4, 0)
}

#[inline]
pub fn legacy_handle_syscall6(id: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    crate::syscall::handle_syscall(id, a0, a1, a2, a3, a4, a5)
}

#[inline(always)]
fn trace_in(_id: u64, _a0: u64, _a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) {
    #[cfg(feature = "nonos-syscall-trace")]
    {
        crate::log_debug!("syscall in: id={} a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x}", _id, _a0, _a1, _a2, _a3, _a4, _a5);
    }
}

#[inline(always)]
fn trace_out(_id: u64, _ret: u64) {
    #[cfg(feature = "nonos-syscall-trace")]
    {
        crate::log_debug!("syscall out: id={} ret={:#x}", _id, _ret);
    }
}

#[no_mangle]
pub extern "C" fn nonos_legacy_syscall_entry() {
    unsafe {
        let (id, a0, a1, a2): (u64, u64, u64, u64);
        core::arch::asm!(
            "mov {id}, rax",
            "mov {a0}, rdi",
            "mov {a1}, rsi",
            "mov {a2}, rdx",
            id = out(reg) id,
            a0 = out(reg) a0,
            a1 = out(reg) a1,
            a2 = out(reg) a2,
            options(nostack, preserves_flags),
        );

        trace_in(id, a0, a1, a2, 0, 0, 0);
        let ret = crate::syscall::handle_syscall(id, a0, a1, a2, 0, 0, 0);
        trace_out(id, ret);

        core::arch::asm!(
            "mov rax, {ret}",
            ret = in(reg) ret,
            options(nostack, preserves_flags),
        );
    }
}
