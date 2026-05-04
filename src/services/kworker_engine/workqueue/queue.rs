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

use super::execute::execute_work_item;
use super::stats::WORKER_STATS;
use super::types::{WorkItem, WorkQueue};
use spin::Mutex;

static WORK_QUEUE: Mutex<WorkQueue> = Mutex::new(WorkQueue::new());

pub(crate) fn queue_work(item: WorkItem) -> Result<(), ()> {
    WORK_QUEUE.lock().enqueue(item)
}

pub(crate) fn queue_work_batch(items: &[WorkItem]) -> usize {
    let mut queue = WORK_QUEUE.lock();
    let mut queued = 0;
    for &item in items {
        if queue.enqueue(item).is_ok() {
            queued += 1;
        } else {
            break;
        }
    }
    queued
}

pub(crate) fn process_work() -> usize {
    let mut processed = 0;
    loop {
        let item = {
            let mut queue = WORK_QUEUE.lock();
            if queue.is_empty() {
                None
            } else {
                queue.dequeue()
            }
        };
        match item {
            Some(work) => {
                execute_work_item(work);
                processed += 1;
                WORKER_STATS.lock().items_processed += 1;
            }
            None => break,
        }
    }
    processed
}
