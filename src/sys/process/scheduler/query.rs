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

use core::sync::atomic::Ordering;
use super::state::{TASKS, CURRENT_TASK, TASK_COUNT, SCHEDULER_INIT};
use super::super::{TaskState, MAX_TASKS};

pub fn current_id() -> u32 {
    CURRENT_TASK.load(Ordering::Relaxed)
}

pub fn task_count() -> u32 {
    TASK_COUNT.load(Ordering::Relaxed)
}

pub fn is_init() -> bool {
    SCHEDULER_INIT.load(Ordering::Relaxed)
}

pub fn get_task_info(id: u32) -> Option<(TaskState, &'static [u8])> {
    unsafe {
        for i in 0..MAX_TASKS {
            if TASKS[i].id == id && TASKS[i].state != TaskState::Empty {
                return Some((TASKS[i].state, TASKS[i].get_name()));
            }
        }
    }
    None
}

pub fn for_each_task<F: FnMut(u32, TaskState, &[u8])>(mut f: F) {
    unsafe {
        for i in 0..MAX_TASKS {
            if TASKS[i].state != TaskState::Empty {
                f(TASKS[i].id, TASKS[i].state, TASKS[i].get_name());
            }
        }
    }
}
