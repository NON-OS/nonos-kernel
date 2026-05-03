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

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::process::{get_process, ProcessState};

static CAPSULE_PID: AtomicU32 = AtomicU32::new(0);
static GENERATION: AtomicU64 = AtomicU64::new(0);

pub(super) fn set_alive(pid: u32) {
    CAPSULE_PID.store(pid, Ordering::SeqCst);
    GENERATION.fetch_add(1, Ordering::SeqCst);
}

pub(super) fn mark_dead() {
    CAPSULE_PID.store(0, Ordering::SeqCst);
}

pub(super) fn pid() -> u32 {
    CAPSULE_PID.load(Ordering::SeqCst)
}

// Liveness is verified against the process table on every check so a
// capsule that exited or zombied is observed deterministically by the
// next IPC attempt; the stored pid is cleared so subsequent checks
// return false without re-walking the table.
pub(super) fn is_alive() -> bool {
    let pid = CAPSULE_PID.load(Ordering::SeqCst);
    if pid == 0 {
        return false;
    }
    match get_process(pid) {
        Some(pcb) => {
            let alive = matches!(
                *pcb.state.lock(),
                ProcessState::New
                    | ProcessState::Ready
                    | ProcessState::Running
                    | ProcessState::Sleeping
                    | ProcessState::Stopped
            );
            if !alive {
                mark_dead();
            }
            alive
        }
        None => {
            mark_dead();
            false
        }
    }
}

pub fn current_generation() -> u64 {
    GENERATION.load(Ordering::SeqCst)
}
