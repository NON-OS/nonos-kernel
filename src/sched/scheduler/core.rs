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

use core::ptr::addr_of_mut;
use spin::{Mutex, Once};
use crate::sched::task::Task;
use crate::sched::runqueue::RunQueue;
use crate::sched::realtime;
use super::types::Scheduler;

static RUNQUEUE: Once<Mutex<RunQueue>> = Once::new();

pub(super) fn get_queue() -> &'static Mutex<RunQueue> {
    RUNQUEUE.call_once(|| Mutex::new(RunQueue::new()))
}

static mut GLOBAL_SCHEDULER: Option<Scheduler> = None;

pub fn init() {
    // SAFETY: Single-threaded initialization during kernel boot.
    unsafe { GLOBAL_SCHEDULER = Some(Scheduler { running_tasks: 0 }); }
    get_queue().lock().clear();
    realtime::init();
}

pub fn get() -> Option<&'static Scheduler> {
    // SAFETY: Read-only access after initialization.
    unsafe {
        let ptr = addr_of_mut!(GLOBAL_SCHEDULER);
        (*ptr).as_ref()
    }
}

pub fn spawn(task: Task) {
    if task.priority == crate::sched::task::Priority::RealTime {
        realtime::spawn_realtime(task);
    } else {
        get_queue().lock().push(task);
    }
}

pub fn run() -> ! {
    loop {
        realtime::run_realtime_tasks();

        let mut rq = get_queue().lock();
        if let Some(mut task) = rq.pop() {
            task.run();
            if !task.is_complete() {
                rq.push(task);
            }
        } else {
            crate::arch::idle_cpu();
        }
    }
}

pub fn enter() -> ! {
    run()
}
