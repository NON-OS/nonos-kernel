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

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use spin::Once;
use super::constants::MAX_CPUS;
use super::percpu_queue::PerCpuRunQueue;
use super::types::LoadBalanceState;

struct CpuQueueSlot(Once<PerCpuRunQueue>);
impl CpuQueueSlot {
    const fn new() -> Self { Self(Once::new()) }
}

static CPU_QUEUES: [CpuQueueSlot; MAX_CPUS] = {
    const SLOT: CpuQueueSlot = CpuQueueSlot::new();
    [SLOT; MAX_CPUS]
};

pub(super) static GLOBAL_TICK: AtomicU64 = AtomicU64::new(0);
pub(super) static LOAD_BALANCE_STATE: LoadBalanceState = LoadBalanceState::new();
static ACTIVE_CPU_COUNT: AtomicUsize = AtomicUsize::new(1);
static SMP_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init_cpu_queue(cpu_id: usize) {
    CPU_QUEUES[cpu_id].0.call_once(|| PerCpuRunQueue::new(cpu_id));
    if cpu_id == 0 {
        SMP_INITIALIZED.store(true, Ordering::Release);
    } else {
        ACTIVE_CPU_COUNT.fetch_add(1, Ordering::Release);
    }
}

pub fn get_cpu_queue(cpu_id: usize) -> &'static PerCpuRunQueue {
    CPU_QUEUES[cpu_id].0.get().expect("CPU queue not initialized")
}

pub fn active_cpu_count() -> usize { ACTIVE_CPU_COUNT.load(Ordering::Relaxed) }

pub fn is_smp_initialized() -> bool { SMP_INITIALIZED.load(Ordering::Acquire) }

pub fn for_each_cpu_queue<F: FnMut(usize, &PerCpuRunQueue)>(mut f: F) {
    let count = active_cpu_count();
    for cpu_id in 0..count {
        if let Some(queue) = CPU_QUEUES[cpu_id].0.get() {
            f(cpu_id, queue);
        }
    }
}
