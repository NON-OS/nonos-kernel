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

use super::current::slot_mut;
use super::enable::enable;
use super::restore::restore;

// First-use lazy enable. Returns true if the current task's FP slot
// was found, enabled, and restored — the caller eret's without
// advancing ELR. Returns false if no task slot is registered; the
// caller must fail closed.
pub fn try_enable_for_current_task() -> bool {
    let slot = match slot_mut() {
        Some(s) => s,
        None => return false,
    };
    // Grant EL0/EL1 FP access, then load the task's saved register
    // file. If never used before, `ctx` is zeroed by FpSimdSlot::zeroed,
    // which is the architectural reset state.
    enable();
    // SAFETY: CPACR_EL1.FPEN was just granted, ctx is owned by this
    // task's slot, and we are on the CPU running that task.
    unsafe { restore(&slot.ctx) };
    slot.enabled = true;
    // Any FP op after restore can dirty the registers; mark dirty so
    // the next save-on-deschedule actually saves.
    slot.dirty = true;
    true
}
