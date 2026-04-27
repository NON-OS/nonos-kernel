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

use super::types::{raise_softirq, SoftIrqType};
use spin::Mutex;

pub(crate) struct SoftIrqStats {
    pub count: [u64; 9],
    pub time_ns: [u64; 9],
}

pub(super) static STATS: Mutex<SoftIrqStats> =
    Mutex::new(SoftIrqStats { count: [0; 9], time_ns: [0; 9] });

struct Tasklet {
    func: fn(u64),
    data: u64,
    pending: bool,
}
static TASKLET_QUEUE: Mutex<[Option<Tasklet>; 32]> = Mutex::new([const { None }; 32]);
static RCU_CALLBACKS: Mutex<[Option<fn()>; 16]> = Mutex::new([None; 16]);

pub(crate) fn get_stats() -> SoftIrqStats {
    let stats = STATS.lock();
    SoftIrqStats { count: stats.count, time_ns: stats.time_ns }
}

pub(crate) fn schedule_tasklet(func: fn(u64), data: u64) {
    let mut queue = TASKLET_QUEUE.lock();
    for slot in queue.iter_mut() {
        if slot.is_none() {
            *slot = Some(Tasklet { func, data, pending: true });
            raise_softirq(SoftIrqType::Tasklet);
            return;
        }
    }
}

pub(super) fn process_tasklets() {
    let mut pending_tasks = [(None::<fn(u64)>, 0u64); 32];
    let mut task_count = 0;
    {
        let mut queue = TASKLET_QUEUE.lock();
        for slot in queue.iter_mut() {
            if let Some(tasklet) = slot {
                if tasklet.pending {
                    pending_tasks[task_count] = (Some(tasklet.func), tasklet.data);
                    task_count += 1;
                    *slot = None;
                }
            }
        }
    }
    for i in 0..task_count {
        if let (Some(f), d) = pending_tasks[i] {
            f(d);
        }
    }
}

pub(crate) fn call_rcu(callback: fn()) {
    let mut callbacks = RCU_CALLBACKS.lock();
    for slot in callbacks.iter_mut() {
        if slot.is_none() {
            *slot = Some(callback);
            raise_softirq(SoftIrqType::Rcu);
            return;
        }
    }
}

pub(super) fn process_rcu_callbacks() {
    let mut pending_cbs = [None::<fn()>; 16];
    let mut cb_count = 0;
    {
        let mut callbacks = RCU_CALLBACKS.lock();
        for slot in callbacks.iter_mut() {
            if let Some(cb) = slot.take() {
                pending_cbs[cb_count] = Some(cb);
                cb_count += 1;
            }
        }
    }
    for i in 0..cb_count {
        if let Some(cb) = pending_cbs[i] {
            cb();
        }
    }
}
