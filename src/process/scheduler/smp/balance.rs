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
use super::constants::{MAX_QUEUE_IMBALANCE, MIGRATION_THRESHOLD};
use super::state::{active_cpu_count, for_each_cpu_queue, get_cpu_queue};
use super::types::CpuLoad;
use core::sync::atomic::Ordering;

pub fn try_load_balance(caller_cpu: usize) {
    let cpu_count = active_cpu_count();
    if cpu_count <= 1 {
        return;
    }
    let mut loads: [CpuLoad; 256] = [CpuLoad { cpu_id: 0, queue_len: 0, last_tick: 0 }; 256];
    let mut count = 0;
    for_each_cpu_queue(|cpu_id, queue| {
        if count < 256 {
            loads[count] = CpuLoad {
                cpu_id,
                queue_len: queue.len(),
                last_tick: queue.tick_count.load(Ordering::Relaxed),
            };
            count += 1;
        }
    });
    let (busiest, idlest) = find_busiest_and_idlest(&loads[..count], caller_cpu);
    if let (Some(b), Some(i)) = (busiest, idlest) {
        if b.queue_len > i.queue_len + MAX_QUEUE_IMBALANCE {
            migrate_tasks(b.cpu_id, i.cpu_id, (b.queue_len - i.queue_len) / 2);
        }
    }
}

fn find_busiest_and_idlest(
    loads: &[CpuLoad],
    caller_cpu: usize,
) -> (Option<CpuLoad>, Option<CpuLoad>) {
    if loads.is_empty() {
        return (None, None);
    }
    let mut busiest: Option<CpuLoad> = None;
    let mut idlest: Option<CpuLoad> = None;
    for load in loads.iter() {
        if load.cpu_id == caller_cpu {
            continue;
        }
        match busiest {
            None => busiest = Some(*load),
            Some(b) if load.queue_len > b.queue_len => busiest = Some(*load),
            _ => {}
        }
        match idlest {
            None => idlest = Some(*load),
            Some(i) if load.queue_len < i.queue_len => idlest = Some(*load),
            _ => {}
        }
    }
    (busiest, idlest)
}

fn migrate_tasks(from_cpu: usize, to_cpu: usize, count: usize) {
    if count < MIGRATION_THRESHOLD || from_cpu == to_cpu {
        return;
    }
    let from_queue = match get_cpu_queue(from_cpu) {
        Some(q) => q,
        None => return,
    };
    let to_queue = match get_cpu_queue(to_cpu) {
        Some(q) => q,
        None => return,
    };
    for _ in 0..count {
        if let Some(task) = steal_migratable_task(from_cpu, to_cpu) {
            to_queue.enqueue(task);
            to_queue.stats.migrations_in.fetch_add(1, Ordering::Relaxed);
            from_queue.stats.migrations_out.fetch_add(1, Ordering::Relaxed);
        } else {
            break;
        }
    }
    crate::smp::send_reschedule_ipi(to_cpu);
}

fn steal_migratable_task(from_cpu: usize, to_cpu: usize) -> Option<Task> {
    let from_queue = get_cpu_queue(from_cpu)?;
    let mut queue = from_queue.queue.lock();
    let pos = queue.iter().position(|t| t.affinity.allowed_cpus.contains(&(to_cpu as u32)))?;
    from_queue.stats.steals.fetch_add(1, Ordering::Relaxed);
    queue.remove(pos)
}
