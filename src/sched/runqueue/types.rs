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

use alloc::collections::VecDeque;
use crate::sched::task::Task;

pub struct RunQueue {
    queue: VecDeque<Task>,
}

impl RunQueue {
    pub fn new() -> Self {
        Self { queue: VecDeque::new() }
    }

    pub fn push(&mut self, task: Task) {
        self.queue.push_back(task);
    }

    pub fn pop(&mut self) -> Option<Task> {
        self.queue.pop_front()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn clear(&mut self) {
        self.queue.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn remove_by_id(&mut self, task_id: u64) -> Option<Task> {
        if let Some(pos) = self.queue.iter().position(|t| t.id == task_id) {
            self.queue.remove(pos)
        } else {
            None
        }
    }
}
