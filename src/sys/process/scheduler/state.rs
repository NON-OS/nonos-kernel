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

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, AtomicBool, Ordering};
use super::super::{Task, MAX_TASKS};

pub(super) static mut TASKS: [Task; MAX_TASKS] = [Task::empty(); MAX_TASKS];
pub(super) static CURRENT_TASK: AtomicU32 = AtomicU32::new(0);
pub(super) static NEXT_TASK_ID: AtomicU32 = AtomicU32::new(1);
pub(super) static TASK_COUNT: AtomicU32 = AtomicU32::new(0);
pub(super) static SCHEDULER_INIT: AtomicBool = AtomicBool::new(false);
pub(super) static SCHEDULER_LOCK: AtomicBool = AtomicBool::new(false);
pub(super) static TIME_QUANTUM: AtomicU64 = AtomicU64::new(20_000_000);
pub(super) static CURRENT_SLICE_END: AtomicU64 = AtomicU64::new(0);
pub(super) static CONTEXT_SWITCHES: AtomicU64 = AtomicU64::new(0);
pub(super) static SCHEDULER_POLICY: AtomicU8 = AtomicU8::new(1);

pub(super) fn lock_scheduler() {
    while SCHEDULER_LOCK.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
}

pub(super) fn unlock_scheduler() {
    SCHEDULER_LOCK.store(false, Ordering::Release);
}
