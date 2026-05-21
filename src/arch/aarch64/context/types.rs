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

// Per-task transition records carried on the PCB. UserEntry is the
// first-entry context the scheduler hands to `enter_user`; SavedUser
// is the snapshot a trap-entry trampoline writes when an EL0 task is
// preempted into EL1. Both are read by `.S` helpers via documented
// field offsets — do not reorder.

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UserEntry {
    // ELR_EL1 target — capsule entry VA. Must be canonical user VA.
    pub entry: u64,
    // SP_EL0 — capsule user stack top. Must be canonical user VA.
    pub user_sp: u64,
    // SPSR_EL1 at eret time. M[3:0] = 0 (EL0t), DAIF as the task expects.
    pub spsr: u64,
    // SP_EL1 to install before eret so the next EL0->EL1 trap lands on
    // this task's kernel stack top, not whatever the kernel last used.
    pub kernel_sp: u64,
    // x0..x7 at user entry. argv/envc/cap-handle live here.
    pub args: [u64; 8],
}

impl UserEntry {
    pub const fn zeroed() -> Self {
        Self { entry: 0, user_sp: 0, spsr: 0, kernel_sp: 0, args: [0; 8] }
    }
}

// Snapshot for resume-from-preempt. Mirrors what the trap-entry path
// (see vectors.S SAVE_GPRS + SAVE_SYSREGS_USER) writes into the frame,
// plus the per-task kernel sp top so resume can re-install SP_EL1 even
// if the task migrates to a different CPU later.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SavedUser {
    // x0..x30 in numeric order.
    pub gprs: [u64; 31],
    // SP_EL0 at trap time.
    pub sp_el0: u64,
    // ELR_EL1 (user return PC) captured by SAVE_SYSREGS_USER.
    pub elr_el1: u64,
    // SPSR_EL1 captured by SAVE_SYSREGS_USER.
    pub spsr_el1: u64,
    // Per-task kernel sp top to install into SP_EL1 before eret.
    pub kernel_sp: u64,
}

impl SavedUser {
    pub const fn zeroed() -> Self {
        Self { gprs: [0; 31], sp_el0: 0, elr_el1: 0, spsr_el1: 0, kernel_sp: 0 }
    }
}
