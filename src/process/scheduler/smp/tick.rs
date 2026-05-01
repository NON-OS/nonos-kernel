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

use super::balance::try_load_balance;
use super::constants::LOAD_BALANCE_INTERVAL_TICKS;
use super::state::{get_cpu_queue, GLOBAL_TICK, LOAD_BALANCE_STATE};
use core::sync::atomic::Ordering;

pub fn smp_tick(cpu_id: usize) -> bool {
    let tick = GLOBAL_TICK.fetch_add(1, Ordering::Relaxed);
    let queue = match get_cpu_queue(cpu_id) {
        Some(q) => q,
        None => return false,
    };
    queue.tick_count.fetch_add(1, Ordering::Relaxed);
    let remaining = queue.slice_remaining.load(Ordering::Relaxed);
    if remaining > 0 {
        let new_remaining = remaining.saturating_sub(1);
        queue.slice_remaining.store(new_remaining, Ordering::Relaxed);
        if new_remaining == 0 {
            preempt_current(cpu_id);
            if LOAD_BALANCE_STATE.should_balance(tick, LOAD_BALANCE_INTERVAL_TICKS) {
                try_load_balance(cpu_id);
                LOAD_BALANCE_STATE.mark_balanced(tick);
            }
            return true;
        }
    } else if queue.current().is_none() && !queue.is_empty() {
        return true;
    }
    if tick % LOAD_BALANCE_INTERVAL_TICKS == 0 && cpu_id == 0 {
        try_load_balance(cpu_id);
        LOAD_BALANCE_STATE.mark_balanced(tick);
    }
    false
}

fn preempt_current(cpu_id: usize) {
    let queue = match get_cpu_queue(cpu_id) {
        Some(q) => q,
        None => return,
    };
    let mut current = queue.current_task.lock();
    if let Some(task) = current.take() {
        if !task.complete {
            drop(current);
            queue.enqueue(task);
        }
    }
}
