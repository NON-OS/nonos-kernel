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
use super::enable::{disable, enable_initial, mark_dirty};
use super::restore::restore;
use super::save::save;

// Save the outgoing task's FP context if dirty, then set FS=Off. The
// scheduler calls this when descheduling a user task; not on every
// trap. If the slot is clean or no current slot, just clamp FS=Off.
pub fn save_outgoing() {
    let slot = match slot_mut() {
        Some(s) => s,
        None => {
            disable();
            return;
        }
    };
    if slot.enabled && slot.dirty {
        // SAFETY: slot.enabled => FS is non-Off on this hart; f-regs
        // hold the task's live state.
        unsafe { save(&mut slot.ctx) };
        slot.valid = true;
        slot.dirty = false;
    }
    disable();
    slot.enabled = false;
}

// Prepare the incoming task. If it has a valid snapshot, set FS=Initial,
// restore, then mark FS=Dirty so the save path treats the f-regs as
// live without needing a re-trap. Otherwise leave FS=Off so the first
// FP op traps into lazy enable.
pub fn prepare_incoming() {
    let slot = match slot_mut() {
        Some(s) => s,
        None => {
            disable();
            return;
        }
    };
    if slot.valid {
        enable_initial();
        // SAFETY: FS just set to Initial.
        unsafe { restore(&slot.ctx) };
        mark_dirty();
        slot.enabled = true;
        slot.dirty = false;
    } else {
        disable();
        slot.enabled = false;
    }
}
