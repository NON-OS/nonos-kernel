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
use super::enable::{disable, enable};
use super::restore::restore;
use super::save::save;

// Save the outgoing task's FP context if dirty, then disable FPEN.
// Called by the scheduler when actually descheduling a user task; not
// called on every trap so a task that runs without yielding keeps FPEN
// granted and avoids a re-trap on the next FP op. Idempotent: if no
// current slot or slot is clean, just disable FPEN as a fail-closed.
pub fn save_outgoing() {
    let slot = match slot_mut() {
        Some(s) => s,
        None => {
            disable();
            return;
        }
    };
    if slot.enabled && slot.dirty {
        // SAFETY: slot.enabled => FPEN is granted on this CPU; the
        // task's q-regs hold its live state.
        unsafe { save(&mut slot.ctx) };
        slot.valid = true;
        slot.dirty = false;
    }
    disable();
    slot.enabled = false;
}

// Prepare the incoming task. If it has a valid snapshot, restore and
// grant FPEN — the task can keep computing without a lazy-enable
// re-trap. If not, leave FPEN disabled so the first FP op traps into
// the lazy-enable path. Always called by the scheduler before eret.
pub fn prepare_incoming() {
    let slot = match slot_mut() {
        Some(s) => s,
        None => {
            disable();
            return;
        }
    };
    if slot.valid {
        enable();
        // SAFETY: FPEN just granted; ctx is the task's saved snapshot.
        unsafe { restore(&slot.ctx) };
        slot.enabled = true;
        slot.dirty = false;
    } else {
        disable();
        slot.enabled = false;
    }
}
