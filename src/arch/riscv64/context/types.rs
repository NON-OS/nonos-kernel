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

// First-entry context the scheduler hands to riscv64_enter_user.
// Field offsets are stable — referenced by enter_user.S.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UserEntry {
    pub entry: u64,         // sepc
    pub user_sp: u64,       // sp at sret time
    pub sstatus: u64,       // SPP=0, SPIE=1, FS=Off, VS=Off, etc.
    pub kernel_sp: u64,     // sscratch primer = per-hart kernel-sp top
    pub args: [u64; 8],     // a0..a7
}

impl UserEntry {
    pub const fn zeroed() -> Self {
        Self { entry: 0, user_sp: 0, sstatus: 0, kernel_sp: 0, args: [0; 8] }
    }
}

// Snapshot for resume-from-preempt. gprs holds x1..x31 in numeric order
// (x0 is hardwired zero, never stored). sp lives at gprs[1] (= x2).
// Layout consumed by resume_user.S — do not reorder.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SavedUser {
    pub gprs: [u64; 31],
    pub sepc: u64,
    pub sstatus: u64,
    pub kernel_sp: u64,
}

impl SavedUser {
    pub const fn zeroed() -> Self {
        Self { gprs: [0; 31], sepc: 0, sstatus: 0, kernel_sp: 0 }
    }
}
