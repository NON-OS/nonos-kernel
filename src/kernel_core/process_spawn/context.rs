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

use crate::process::core::Pid;
use crate::process::core::suspend::save_interrupt_context;
use crate::sched::Context;

const INITIAL_RFLAGS: u64 = 0x202;

pub(crate) fn setup_initial_context(pid: Pid, entry_point: u64, stack_top: u64) {
    // x86-64 ABI requires rsp ≡ 8 (mod 16) at function entry, as if a `call`
    // pushed an 8-byte return address. context_restore_asm uses `ret` to jump
    // to entry_point, which pops 8 bytes, so we pre-subtract 8 here so that
    // rsp is correctly aligned when the entry function's prologue runs.
    let adjusted_rsp = stack_top - 8;
    let ctx = Context {
        rax: 0, rbx: 0, rcx: 0, rdx: 0,
        rsi: 0, rdi: 0, rbp: adjusted_rsp, rsp: adjusted_rsp,
        r8: 0, r9: 0, r10: 0, r11: 0,
        r12: 0, r13: 0, r14: 0, r15: 0,
        rip: entry_point,
        rflags: INITIAL_RFLAGS,
    };
    save_interrupt_context(pid, ctx);
}
