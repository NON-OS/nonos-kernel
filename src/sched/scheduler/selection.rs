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

use core::sync::atomic::Ordering;
use super::process::get_runnable_pids;
use super::preemption::{CURRENT_TIME_SLICE, DEFAULT_TIME_SLICE};

pub fn select_next_process() -> Option<u32> {
    use crate::process::nonos_core::{PROCESS_TABLE, ProcessState, Priority};

    let runnable = get_runnable_pids();
    if runnable.is_empty() {
        return None;
    }

    for &pid in &runnable {
        if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
            let prio = *pcb.priority.lock();
            let state = *pcb.state.lock();
            if state == ProcessState::Ready && prio == Priority::High {
                return Some(pid);
            }
        }
    }

    for &pid in &runnable {
        if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
            let prio = *pcb.priority.lock();
            let state = *pcb.state.lock();
            if state == ProcessState::Ready && prio == Priority::Normal {
                return Some(pid);
            }
        }
    }

    for &pid in &runnable {
        if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
            let state = *pcb.state.lock();
            if state == ProcessState::Ready {
                return Some(pid);
            }
        }
    }

    None
}

pub fn switch_to_process(pid: u32) {
    use crate::process::nonos_core::{PROCESS_TABLE, ProcessState, CURRENT_PID};

    if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
        *pcb.state.lock() = ProcessState::Running;
    }

    CURRENT_PID.store(pid, Ordering::SeqCst);
    CURRENT_TIME_SLICE.store(DEFAULT_TIME_SLICE, Ordering::Relaxed);

    if let Some(ctx) = crate::process::nonos_core::INTERRUPT_SAVED_CONTEXTS.write().remove(&pid) {
        crate::process::nonos_core::clear_interrupt_context(pid);
        ctx.restore();
    }
}
