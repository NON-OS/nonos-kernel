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

// Per-capsule lifecycle state. One static instance per capsule, owned
// by the kernel-side capsule module. `set_alive` is called by the
// spawn path; `mark_dead` is called by `is_alive` when the process
// table shows the capsule has exited.
pub struct CapsuleState {
    pid: AtomicU32,
    generation: AtomicU64,
}

impl CapsuleState {
    pub const fn new() -> Self {
        Self { pid: AtomicU32::new(0), generation: AtomicU64::new(0) }
    }

    // Record a freshly-spawned capsule. Bumps the generation so any
    // in-flight client request issued against the previous epoch
    // returns ESTALE on the next generation check, even if its
    // request_id collides.
    pub fn set_alive(&self, pid: u32) {
        self.pid.store(pid, Ordering::SeqCst);
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    pub fn mark_dead(&self) {
        self.pid.store(0, Ordering::SeqCst);
    }

    pub fn pid(&self) -> u32 {
        self.pid.load(Ordering::SeqCst)
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    // Liveness re-checked against the process table on every call so a
    // capsule that exited or zombied is observed deterministically by
    // the next request. The stored pid is cleared on observed death so
    // subsequent checks short-circuit without re-walking the table.
    pub fn is_alive(&self) -> bool {
        let pid = self.pid.load(Ordering::SeqCst);
        if pid == 0 {
            return false;
        }
        match get_process(pid) {
            Some(pcb) => {
                // Alive set: every non-terminal `ProcessState`.
                // `Zombie(_)` and `Terminated(_)` are the dead states.
                let alive = matches!(
                    *pcb.state.lock(),
                    ProcessState::New
                        | ProcessState::Ready
                        | ProcessState::Running
                        | ProcessState::Sleeping
                        | ProcessState::Stopped
                );
                if !alive {
                    self.mark_dead();
                }
                alive
            }
            None => {
                self.mark_dead();
                false
            }
        }
    }
}
