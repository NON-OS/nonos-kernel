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

use super::types::{AsyncTask, AsyncTaskPriority};

pub(super) struct PriorityTaskQueue {
    pub(super) critical: VecDeque<AsyncTask>,
    pub(super) high: VecDeque<AsyncTask>,
    pub(super) normal: VecDeque<AsyncTask>,
    pub(super) low: VecDeque<AsyncTask>,
    pub(super) idle: VecDeque<AsyncTask>,
}

impl PriorityTaskQueue {
    pub(super) const fn new() -> Self {
        Self {
            critical: VecDeque::new(),
            high: VecDeque::new(),
            normal: VecDeque::new(),
            low: VecDeque::new(),
            idle: VecDeque::new(),
        }
    }

    pub(super) fn push(&mut self, task: AsyncTask) {
        match task.priority {
            AsyncTaskPriority::Critical => self.critical.push_back(task),
            AsyncTaskPriority::High => self.high.push_back(task),
            AsyncTaskPriority::Normal => self.normal.push_back(task),
            AsyncTaskPriority::Low => self.low.push_back(task),
            AsyncTaskPriority::Idle => self.idle.push_back(task),
        }
    }

    pub(super) fn total_len(&self) -> usize {
        self.critical.len() + self.high.len() + self.normal.len() +
        self.low.len() + self.idle.len()
    }

    pub(super) fn pending_count(&self) -> usize {
        self.critical.iter().filter(|t| !t.complete).count() +
        self.high.iter().filter(|t| !t.complete).count() +
        self.normal.iter().filter(|t| !t.complete).count() +
        self.low.iter().filter(|t| !t.complete).count() +
        self.idle.iter().filter(|t| !t.complete).count()
    }
}
