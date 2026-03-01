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

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __x86_indirect_thunk_rax() {
    core::arch::naked_asm!(
        "call 2f",
        "1:",
        "pause",
        "lfence",
        "jmp 1b",
        "2:",
        "mov [rsp], rax",
        "ret",
    );
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __x86_indirect_thunk_rbx() {
    core::arch::naked_asm!(
        "call 2f",
        "1:",
        "pause",
        "lfence",
        "jmp 1b",
        "2:",
        "mov [rsp], rbx",
        "ret",
    );
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __x86_indirect_thunk_rcx() {
    core::arch::naked_asm!(
        "call 2f",
        "1:",
        "pause",
        "lfence",
        "jmp 1b",
        "2:",
        "mov [rsp], rcx",
        "ret",
    );
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __x86_indirect_thunk_rdx() {
    core::arch::naked_asm!(
        "call 2f",
        "1:",
        "pause",
        "lfence",
        "jmp 1b",
        "2:",
        "mov [rsp], rdx",
        "ret",
    );
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __x86_indirect_thunk_rsi() {
    core::arch::naked_asm!(
        "call 2f",
        "1:",
        "pause",
        "lfence",
        "jmp 1b",
        "2:",
        "mov [rsp], rsi",
        "ret",
    );
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __x86_indirect_thunk_rdi() {
    core::arch::naked_asm!(
        "call 2f",
        "1:",
        "pause",
        "lfence",
        "jmp 1b",
        "2:",
        "mov [rsp], rdi",
        "ret",
    );
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __x86_indirect_thunk_r8() {
    core::arch::naked_asm!(
        "call 2f",
        "1:",
        "pause",
        "lfence",
        "jmp 1b",
        "2:",
        "mov [rsp], r8",
        "ret",
    );
}
