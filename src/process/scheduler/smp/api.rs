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

use super::super::task::Task;
use super::balance::try_load_balance;
use super::spawn::{run_local, spawn_on_cpu, spawn_smp};
use super::state::{
    active_cpu_count, for_each_cpu_queue, get_cpu_queue, init_cpu_queue, is_smp_initialized,
};
use super::tick::smp_tick;
use crate::smp::cpu_id;

pub fn init_smp_scheduler() {
    init_cpu_queue(0);
}
pub fn init_ap_scheduler(cpu_id: usize) {
    init_cpu_queue(cpu_id);
}
pub fn spawn(task: Task) -> usize {
    spawn_smp(task)
}
pub fn spawn_pinned(task: Task, cpu_id: usize) {
    spawn_on_cpu(task, cpu_id);
}
pub fn tick() -> bool {
    smp_tick(cpu_id() as usize)
}
pub fn schedule_local() {
    run_local();
}
pub fn yield_cpu() {
    let cpu = cpu_id() as usize;
    if let Some(queue) = get_cpu_queue(cpu) {
        let mut current = queue.current_task.lock();
        if let Some(task) = current.take() {
            drop(current);
            if !task.complete {
                queue.enqueue(task);
            }
            run_local();
        }
    }
}

pub fn is_enabled() -> bool {
    is_smp_initialized() && active_cpu_count() > 1
}
pub fn cpu_count() -> usize {
    active_cpu_count()
}

pub fn local_queue_len() -> usize {
    get_cpu_queue(cpu_id() as usize).map(|q| q.len()).unwrap_or(0)
}

pub fn total_runnable() -> usize {
    let mut total = 0;
    for_each_cpu_queue(|_, queue| {
        total += queue.len();
    });
    total
}

pub fn force_balance() {
    try_load_balance(cpu_id() as usize);
}

pub struct SmpSchedStats {
    pub total_tasks: usize,
    pub active_cpus: usize,
    pub per_cpu: [usize; 256],
}

pub fn get_stats() -> SmpSchedStats {
    let mut stats =
        SmpSchedStats { total_tasks: 0, active_cpus: active_cpu_count(), per_cpu: [0; 256] };
    for_each_cpu_queue(|cpu_id, queue| {
        let len = queue.len();
        stats.per_cpu[cpu_id] = len;
        stats.total_tasks += len;
    });
    stats
}
