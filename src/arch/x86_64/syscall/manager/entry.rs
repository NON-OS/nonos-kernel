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

use super::state::SYSCALL_MANAGER;

#[unsafe(naked)]
pub extern "C" fn syscall_entry_asm() {
    core::arch::naked_asm!(
        "swapgs",
        "mov gs:0x10, rsp",
        "mov rsp, gs:0x08",
        "push rbp",
        "push r11",
        "push rcx",
        "push r10",
        "push r9",
        "push r8",
        "mov rcx, r10",
        "push rax",
        "mov rdi, rax",
        "call {handler}",
        "add rsp, 8",
        "pop r8",
        "pop r9",
        "pop r10",
        "pop rcx",
        "pop r11",
        "pop rbp",
        "mov rsp, gs:0x10",
        "swapgs",
        "sysretq",
        handler = sym syscall_handler,
    );
}

#[no_mangle]
pub(super) extern "C" fn syscall_handler(
    number: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
) -> u64 {
    SYSCALL_MANAGER.dispatch(number, [arg1, arg2, arg3, arg4, arg5, arg6])
}
