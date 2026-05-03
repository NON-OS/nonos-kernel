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
use super::super::task::{DeadlineFlags, Task};
use super::queue::{get_scheduler, DeadlineTask};
use super::queue_ops::{enqueue, pick_next, remove_task};
use alloc::vec::Vec;
use core::sync::atomic::Ordering as AO;

pub fn update_runtime(task: &mut Task, runtime: u64) {
    if let Some(ref mut dl) = task.deadline_params {
        dl.remaining_runtime = dl.remaining_runtime.saturating_sub(runtime);
        get_scheduler().lock().stats.runtime_consumed.fetch_add(runtime, AO::Relaxed);
        if dl.remaining_runtime == 0 {
            dl.flags.insert(DeadlineFlags::THROTTLED);
        }
    }
}

pub fn replenishment_timer() {
    let now = crate::sys::clock::get_ticks();
    let mut s = get_scheduler().lock();
    let mut to_replenish: Vec<DeadlineTask> = Vec::new();
    let mut remaining: Vec<DeadlineTask> = Vec::new();
    while let Some(dt) = s.runqueue.pop() {
        let mut task = dt.task;
        if let Some(ref dl) = task.deadline_params {
            if now >= dl.period_start + dl.period {
                task.replenish_deadline();
                s.stats.replenishment_events.fetch_add(1, AO::Relaxed);
                to_replenish.push(DeadlineTask { task });
            } else {
                remaining.push(DeadlineTask { task });
            }
        } else {
            remaining.push(DeadlineTask { task });
        }
    }
    for dt in remaining {
        s.runqueue.push(dt);
    }
    for dt in to_replenish {
        s.runqueue.push(dt);
    }
}

pub fn run_deadline_tasks() {
    replenishment_timer();
    if let Some(mut task) = pick_next() {
        let start = crate::sys::clock::get_ticks();
        task.run();
        let elapsed = crate::sys::clock::get_ticks().saturating_sub(start);
        update_runtime(&mut task, elapsed);
        if !task.is_complete() {
            enqueue(task);
        } else {
            remove_task(task.id);
        }
    }
}
