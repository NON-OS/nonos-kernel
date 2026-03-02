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

use crate::sched::task::{Task, Priority};
use crate::sched::runqueue::RunQueue;
use spin::{Mutex, Once};

static REALTIME_RUNQUEUE: Once<Mutex<RunQueue>> = Once::new();

fn get_rt_queue() -> &'static Mutex<RunQueue> {
    REALTIME_RUNQUEUE.call_once(|| Mutex::new(RunQueue::new()))
}

pub fn init() {
    get_rt_queue().lock().clear();
}

pub fn spawn_realtime(task: Task) {
    if task.priority == Priority::RealTime {
        get_rt_queue().lock().push(task);
    }
}

pub fn run_realtime_tasks() {
    let mut rq = get_rt_queue().lock();
    while let Some(mut task) = rq.pop() {
        task.run();
        if !task.is_complete() {
            rq.push(task);
        }
    }
}

pub fn pending_realtime_tasks() -> usize {
    get_rt_queue().lock().len()
}

pub fn has_realtime_tasks() -> bool {
    !get_rt_queue().lock().is_empty()
}
