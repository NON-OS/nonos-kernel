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

extern crate alloc;
use super::queue::{get_scheduler, DeadlineTask};
use super::super::task::{DeadlineFlags, Task};
use alloc::vec::Vec;
use core::sync::atomic::Ordering as AO;

pub fn pick_next() -> Option<Task> {
    let mut s = get_scheduler().lock();
    while let Some(dt) = s.runqueue.pop() {
        let mut task = dt.task;
        if task.has_missed_deadline() {
            if let Some(ref mut dl) = task.deadline_params {
                dl.deadline_misses += 1;
                dl.flags.insert(DeadlineFlags::DL_OVERRUN);
                s.stats.deadline_misses.fetch_add(1, AO::Relaxed);
                task.replenish_deadline();
            }
        }
        if task.is_throttled() {
            s.stats.throttle_events.fetch_add(1, AO::Relaxed);
            s.runqueue.push(DeadlineTask { task });
            continue;
        }
        return Some(task);
    }
    None
}

pub fn enqueue(task: Task) {
    if !task.is_deadline() {
        return;
    }
    get_scheduler().lock().runqueue.push(DeadlineTask { task });
}

pub fn remove_task(task_id: u64) {
    let mut s = get_scheduler().lock();
    let mut tasks: Vec<DeadlineTask> = Vec::new();
    let mut removed_bw = 0u64;
    while let Some(dt) = s.runqueue.pop() {
        if dt.task.id == task_id {
            if let Some(ref dl) = dt.task.deadline_params {
                removed_bw = dl.bandwidth();
            }
        } else {
            tasks.push(dt);
        }
    }
    for dt in tasks {
        s.runqueue.push(dt);
    }
    s.total_bandwidth = s.total_bandwidth.saturating_sub(removed_bw);
    if removed_bw > 0 {
        s.active_count = s.active_count.saturating_sub(1);
    }
}

pub fn has_runnable() -> bool {
    !get_scheduler().lock().runqueue.is_empty()
}
pub fn task_count() -> u64 {
    get_scheduler().lock().active_count
}
