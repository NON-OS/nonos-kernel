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

use crate::arch::riscv64::interrupts::frame::TrapFrame;

use super::current::slot_mut;
use super::enable::{enable_initial, mark_dirty};
use super::restore::restore;

// First-use lazy FP enable. Returns true if the task slot was found,
// FS flipped, registers restored, and the user's trapping instruction
// can re-run via sret without sepc advance. Returns false when no per-
// task FP slot is wired; caller must fail closed.
pub fn try_enable_for_current_task(frame: &mut TrapFrame) -> bool {
    let slot = match slot_mut() {
        Some(s) => s,
        None => return false,
    };

    // Move sstatus.FS in this CPU to Initial so the restore's fsd
    // instructions don't take the same illegal-instruction trap.
    enable_initial();

    // SAFETY: FS is now Initial; ctx is owned by this task's slot.
    unsafe { restore(&slot.ctx) };

    // Promote FS to Dirty: subsequent FP writes happen anyway, and
    // the next deschedule sees Dirty and runs save.
    mark_dirty();

    // Mirror the FS bits into the frame's sstatus so sret restores
    // FS=Dirty into the user context, not the Off it trapped with.
    frame.sstatus = (frame.sstatus
        & !crate::arch::riscv64::cpu::csr::SSTATUS_FS_MASK)
        | crate::arch::riscv64::cpu::csr::SSTATUS_FS_DIRTY;

    slot.enabled = true;
    slot.dirty = true;
    true
}
