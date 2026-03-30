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

use core::sync::atomic::{AtomicU32, Ordering};
use crate::process::nonos_core::Priority;
use super::super::process::get_runnable_pids;

pub static LAST_SCHEDULED_PID: AtomicU32 = AtomicU32::new(0);

pub fn select_next_process() -> Option<u32> {
    use crate::process::nonos_core::CURRENT_PID;
    let current = CURRENT_PID.load(Ordering::Relaxed);
    let runnable = get_runnable_pids();
    if runnable.is_empty() { return None; }
    let last = LAST_SCHEDULED_PID.load(Ordering::Relaxed);
    if let Some(pid) = select_by_priority(&runnable, last, current, Priority::High) {
        LAST_SCHEDULED_PID.store(pid, Ordering::Relaxed);
        return Some(pid);
    }
    if let Some(pid) = select_by_priority(&runnable, last, current, Priority::Normal) {
        LAST_SCHEDULED_PID.store(pid, Ordering::Relaxed);
        return Some(pid);
    }
    if let Some(pid) = select_any_ready(&runnable, last, current) {
        LAST_SCHEDULED_PID.store(pid, Ordering::Relaxed);
        return Some(pid);
    }
    None
}

fn select_by_priority(pids: &[u32], last: u32, current: u32, prio: crate::process::nonos_core::Priority) -> Option<u32> {
    use crate::process::nonos_core::{PROCESS_TABLE, ProcessState};
    select_round_robin(pids, last, current, |pid| {
        PROCESS_TABLE.find_by_pid(pid).map_or(false, |pcb| {
            *pcb.state.lock() == ProcessState::Ready && *pcb.priority.lock() == prio
        })
    })
}

fn select_any_ready(pids: &[u32], last: u32, current: u32) -> Option<u32> {
    use crate::process::nonos_core::{PROCESS_TABLE, ProcessState};
    select_round_robin(pids, last, current, |pid| {
        PROCESS_TABLE.find_by_pid(pid).map_or(false, |pcb| *pcb.state.lock() == ProcessState::Ready)
    })
}

fn select_round_robin<F>(pids: &[u32], last: u32, current: u32, predicate: F) -> Option<u32>
where F: Fn(u32) -> bool {
    let start_idx = pids.iter().position(|&p| p > last).unwrap_or(0);
    let mut fallback: Option<u32> = None;
    for &pid in &pids[start_idx..] {
        if predicate(pid) {
            if pid != current { return Some(pid); }
            else if fallback.is_none() { fallback = Some(pid); }
        }
    }
    for &pid in &pids[..start_idx] {
        if predicate(pid) {
            if pid != current { return Some(pid); }
            else if fallback.is_none() { fallback = Some(pid); }
        }
    }
    fallback
}