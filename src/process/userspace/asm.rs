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

use super::types::InterruptFrame;

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn jump_to_usermode(entry: u64, stack: u64, arg: u64) -> ! {
    core::arch::naked_asm!(
        "mov ax, 0x23",
        "mov ds, ax",
        "mov es, ax",
        "mov fs, ax",
        "mov gs, ax",
        "push 0x23",
        "push rsi",
        "push 0x202",
        "push 0x1B",
        "push rdi",
        "mov rdi, rdx",
        "xor rax, rax",
        "xor rbx, rbx",
        "xor rcx, rcx",
        "xor rdx, rdx",
        "xor rsi, rsi",
        "xor rbp, rbp",
        "xor r8, r8",
        "xor r9, r9",
        "xor r10, r10",
        "xor r11, r11",
        "xor r12, r12",
        "xor r13, r13",
        "xor r14, r14",
        "xor r15, r15",
        "iretq",
    );
}

pub unsafe fn return_to_usermode(frame: *const InterruptFrame) -> ! {
    let f = unsafe { &*frame };
    const USER_SPACE_MAX: u64 = 0x0000_7FFF_FFFF_FFFF;
    if f.rip > USER_SPACE_MAX || f.rsp > USER_SPACE_MAX || f.rsp == 0 {
        crate::sys::serial::println(b"[FATAL] Invalid user frame");
        crate::arch::x86_64::boot::cpu_ops::halt_loop()
    }
    unsafe { return_to_usermode_asm(frame) }
}

#[unsafe(naked)]
unsafe extern "C" fn return_to_usermode_asm(frame: *const InterruptFrame) -> ! {
    core::arch::naked_asm!("mov rsp, rdi", "mov ax, 0x23", "mov ds, ax", "mov es, ax", "iretq");
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn sysret_to_usermode(rip: u64, rsp: u64, rflags: u64, retval: u64) -> ! {
    core::arch::naked_asm!(
        "mov rax, rdi",
        "shr rax, 47",
        "cmp rax, 0",
        "je 2f",
        "cmp rax, 0x1FFFF",
        "jne 1f",
        "2:",
        "mov rax, rcx",
        "mov rcx, rdi",
        "mov r11, rdx",
        "mov rsp, rsi",
        "xor rbx, rbx",
        "xor rdx, rdx",
        "xor rsi, rsi",
        "xor rdi, rdi",
        "xor rbp, rbp",
        "xor r8, r8",
        "xor r9, r9",
        "xor r10, r10",
        "xor r12, r12",
        "xor r13, r13",
        "xor r14, r14",
        "xor r15, r15",
        "swapgs",
        "sysretq",
        "1:",
        "ud2",
    );
}
