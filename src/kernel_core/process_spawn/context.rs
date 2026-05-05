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

use crate::process::core::suspend::save_interrupt_context;
use crate::process::core::{Pid, PROCESS_TABLE};
use crate::process::userspace::types::InterruptFrame;
use crate::sched::Context;

const INITIAL_RFLAGS: u64 = 0x202;

// Top of the canonical low half. User RIP/RSP must satisfy `<= USER_VA_MAX`
// before any iretq into CPL=3.
const USER_VA_MAX: u64 = 0x0000_7FFF_FFFF_FFFF;

#[derive(Debug, Clone, Copy)]
pub enum UserEntryError {
    NoSuchProcess,
    NonUserEntry,
    NonUserStack,
}

/// Kernel-thread first-run context. Used only by the legacy
/// `spawn_isolated_service` path, where the entry runs in CPL=0. Real
/// capsules go through `setup_initial_user_context`.
pub(crate) fn setup_initial_context(pid: Pid, entry_point: u64, stack_top: u64) {
    // x86-64 ABI requires rsp ≡ 8 (mod 16) at function entry, as if a `call`
    // pushed an 8-byte return address. context_restore_asm uses `ret` to jump
    // to entry_point, which pops 8 bytes, so we pre-subtract 8 here so that
    // rsp is correctly aligned when the entry function's prologue runs.
    let adjusted_rsp = stack_top - 8;
    let ctx = Context {
        rax: 0,
        rbx: 0,
        rcx: 0,
        rdx: 0,
        rsi: 0,
        rdi: 0,
        rbp: adjusted_rsp,
        rsp: adjusted_rsp,
        r8: 0,
        r9: 0,
        r10: 0,
        r11: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rip: entry_point,
        rflags: INITIAL_RFLAGS,
    };
    save_interrupt_context(pid, ctx);
}

/// Capsule first-run context. Builds the iretq frame the scheduler
/// resume hook will push to enter CPL=3 at the capsule's ELF entry on
/// its per-process user stack. Both `entry` and `user_rsp` must be
/// canonical user VAs; a caller-supplied kernel VA is rejected so the
/// hook can never iretq into the kernel half from CPL=3. The hook
/// lands in patch 1.D; this function only stages the frame on the PCB.
pub(crate) fn setup_initial_user_context(
    pid: Pid,
    entry: u64,
    user_rsp: u64,
) -> Result<(), UserEntryError> {
    if entry == 0 || entry > USER_VA_MAX {
        return Err(UserEntryError::NonUserEntry);
    }
    if user_rsp == 0 || user_rsp > USER_VA_MAX {
        return Err(UserEntryError::NonUserStack);
    }
    let pcb = PROCESS_TABLE.find_by_pid(pid).ok_or(UserEntryError::NoSuchProcess)?;
    let frame = InterruptFrame::for_user_entry(entry, user_rsp);
    *pcb.pending_user_entry.lock() = Some(frame);
    Ok(())
}
