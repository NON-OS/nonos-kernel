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

use super::super::task::Task;
use super::constants::DEFAULT_TIME_SLICE;
use super::types::CpuRunQueueStats;
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::Mutex;

pub struct PerCpuRunQueue {
    pub(super) queue: Mutex<VecDeque<Task>>,
    pub(super) current_task: Mutex<Option<Task>>,
    pub(super) slice_remaining: AtomicU32,
    cpu_id: usize,
    pub stats: CpuRunQueueStats,
    pub(super) tick_count: AtomicU64,
}

impl PerCpuRunQueue {
    pub const fn new(cpu_id: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            current_task: Mutex::new(None),
            slice_remaining: AtomicU32::new(0),
            cpu_id,
            stats: CpuRunQueueStats::new(),
            tick_count: AtomicU64::new(0),
        }
    }

    pub fn cpu_id(&self) -> usize {
        self.cpu_id
    }

    pub fn len(&self) -> usize {
        self.queue.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.lock().is_empty()
    }

    pub fn enqueue(&self, task: Task) {
        self.queue.lock().push_back(task);
        self.stats.enqueued.fetch_add(1, Ordering::Relaxed);
    }

    pub fn enqueue_front(&self, task: Task) {
        self.queue.lock().push_front(task);
        self.stats.enqueued.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dequeue(&self) -> Option<Task> {
        let task = self.queue.lock().pop_front();
        if task.is_some() {
            self.stats.dequeued.fetch_add(1, Ordering::Relaxed);
        }
        task
    }

    pub fn pick_next(&self) -> Option<Task> {
        self.set_current(self.dequeue())
    }

    pub fn set_current(&self, task: Option<Task>) -> Option<Task> {
        let mut current = self.current_task.lock();
        let prev = current.take();
        *current = task;
        if current.is_some() {
            self.slice_remaining.store(DEFAULT_TIME_SLICE, Ordering::Relaxed);
        }
        prev
    }

    pub fn current(&self) -> Option<u64> {
        self.current_task.lock().as_ref().map(|t| t.id)
    }
}
