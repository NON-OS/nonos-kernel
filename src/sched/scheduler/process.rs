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

use alloc::collections::{BTreeSet, BTreeMap};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use super::preemption::{SCHEDULER_STATS, NEED_RESCHEDULE};

static PID_RUN_QUEUE: spin::RwLock<BTreeSet<u32>> = spin::RwLock::new(BTreeSet::new());
static SLEEPING_PROCESSES: spin::RwLock<BTreeMap<u32, u64>> = spin::RwLock::new(BTreeMap::new());

pub fn sleep_until(pid: u32, wake_time_ms: u64) {
    use crate::process::nonos_core::{PROCESS_TABLE, ProcessState};

    SLEEPING_PROCESSES.write().insert(pid, wake_time_ms);

    if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
        *pcb.state.lock() = ProcessState::Sleeping;
    }

    remove_from_run_queue(pid);
    crate::log_debug!("Process {} sleeping until {} ms", pid, wake_time_ms);
}

pub fn wake_process(pid: u32) {
    use crate::process::nonos_core::{PROCESS_TABLE, ProcessState};

    SLEEPING_PROCESSES.write().remove(&pid);

    if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
        let mut state = pcb.state.lock();
        if *state == ProcessState::Sleeping {
            *state = ProcessState::Ready;
        }
    }

    add_to_run_queue(pid);
    SCHEDULER_STATS.wakeups.fetch_add(1, Ordering::Relaxed);
    crate::log_debug!("Process {} woken up", pid);
}

pub fn is_sleeping(pid: u32) -> bool {
    SLEEPING_PROCESSES.read().contains_key(&pid)
}

pub fn get_remaining_sleep(pid: u32) -> Option<u64> {
    let sleeping = SLEEPING_PROCESSES.read();
    if let Some(&wake_time) = sleeping.get(&pid) {
        let now = crate::time::timestamp_millis();
        if wake_time > now {
            Some(wake_time - now)
        } else {
            Some(0)
        }
    } else {
        None
    }
}

pub fn add_to_run_queue(pid: u32) {
    PID_RUN_QUEUE.write().insert(pid);
    crate::log_debug!("Process {} added to run queue", pid);
}

pub fn remove_from_run_queue(pid: u32) {
    PID_RUN_QUEUE.write().remove(&pid);
    crate::log_debug!("Process {} removed from run queue", pid);
}

pub fn is_in_run_queue(pid: u32) -> bool {
    PID_RUN_QUEUE.read().contains(&pid)
}

pub fn runnable_process_count() -> usize {
    PID_RUN_QUEUE.read().len()
}

pub fn get_runnable_pids() -> Vec<u32> {
    PID_RUN_QUEUE.read().iter().copied().collect()
}

pub fn wakeup() {
    SCHEDULER_STATS.wakeups.fetch_add(1, Ordering::Relaxed);
    check_sleeping_processes();

    if runnable_process_count() > 0 {
        NEED_RESCHEDULE.store(true, Ordering::SeqCst);
    }
}

pub fn check_sleeping_processes() {
    use crate::process::nonos_core::PROCESS_TABLE;

    let current_time_ms = crate::time::timestamp_millis();

    let pids_to_wake: Vec<u32> = {
        let sleeping = SLEEPING_PROCESSES.read();
        sleeping
            .iter()
            .filter(|(_, &wake_time)| current_time_ms >= wake_time)
            .map(|(&pid, _)| pid)
            .collect()
    };

    for pid in pids_to_wake {
        wake_process(pid);
    }

    let _ = PROCESS_TABLE.get_all_processes();
}
