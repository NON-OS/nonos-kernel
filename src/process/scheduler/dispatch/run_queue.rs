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

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

static PID_RUN_QUEUE: spin::RwLock<BTreeSet<u32>> = spin::RwLock::new(BTreeSet::new());

pub fn add_to_run_queue(pid: u32) {
    let inserted = PID_RUN_QUEUE.write().insert(pid);
    if !inserted {
        return;
    }
    let asid = crate::memory::paging::manager::lookup_asid_for_process(pid).unwrap_or(0);
    crate::sys::serial::print(b"[SCHED] enqueue pid=");
    crate::arch::x86_64::diag::print_hex_u64(pid as u64);
    crate::sys::serial::print(b" asid=");
    crate::arch::x86_64::diag::print_hex_u64(asid as u64);
    crate::sys::serial::println(b"");
}

pub fn remove_from_run_queue(pid: u32) {
    PID_RUN_QUEUE.write().remove(&pid);
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
