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

use super::state::{get_cpu_queue, active_cpu_count, for_each_cpu_queue};
use crate::sched::task::Task;
use crate::smp::cpu_id;

pub fn spawn_smp(task: Task) -> usize {
    let target_cpu = select_target_cpu(&task);
    if let Some(queue) = get_cpu_queue(target_cpu) {
        queue.enqueue(task);
        if target_cpu != cpu_id() as usize {
            crate::smp::send_reschedule_ipi(target_cpu);
        }
    }
    target_cpu
}

fn select_target_cpu(task: &Task) -> usize {
    let current = cpu_id() as usize;
    let cpu_count = active_cpu_count();
    if cpu_count <= 1 { return 0; }
    if !task.affinity.allowed_cpus.is_empty() && !task.affinity.allowed_cpus.contains(&(current as u32)) {
        return task.affinity.allowed_cpus[0] as usize;
    }
    let mut min_len = usize::MAX;
    let mut target = current;
    for_each_cpu_queue(|cpu_id, queue| {
        if task.affinity.allowed_cpus.is_empty() || task.affinity.allowed_cpus.contains(&(cpu_id as u32)) {
            let len = queue.len();
            if len < min_len {
                min_len = len;
                target = cpu_id;
            }
        }
    });
    target
}

pub fn spawn_on_cpu(task: Task, cpu_id: usize) {
    if let Some(queue) = get_cpu_queue(cpu_id) {
        queue.enqueue(task);
        if cpu_id != crate::smp::cpu_id() as usize {
            crate::smp::send_reschedule_ipi(cpu_id);
        }
    }
}

pub fn run_local() {
    let cpu = cpu_id() as usize;
    let queue = match get_cpu_queue(cpu) {
        Some(q) => q,
        None => return,
    };
    if let Some(mut task) = queue.pick_next() {
        task.run();
        if !task.complete {
            queue.enqueue(task);
        }
    }
}
