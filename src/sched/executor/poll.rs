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
use alloc::vec::Vec;

use super::types::AsyncTask;
use super::state::{ASYNC_QUEUE, WOKEN_TASKS};

pub fn poll_async_tasks() {
    poll_async_tasks_limited(usize::MAX)
}

pub fn poll_async_tasks_limited(max_polls: usize) {
    let mut polls_done = 0;
    let mut queue = ASYNC_QUEUE.lock();

    let woken_ids: Vec<u64> = WOKEN_TASKS.read().clone();

    polls_done += poll_priority_queue(&mut queue.critical, &woken_ids, max_polls - polls_done);
    if polls_done >= max_polls { return; }

    polls_done += poll_priority_queue(&mut queue.high, &woken_ids, max_polls - polls_done);
    if polls_done >= max_polls { return; }

    polls_done += poll_priority_queue(&mut queue.normal, &woken_ids, max_polls - polls_done);
    if polls_done >= max_polls { return; }

    polls_done += poll_priority_queue(&mut queue.low, &woken_ids, max_polls - polls_done);
    if polls_done >= max_polls { return; }

    poll_priority_queue(&mut queue.idle, &woken_ids, max_polls - polls_done);
}

fn poll_priority_queue(
    priority_queue: &mut VecDeque<AsyncTask>,
    woken_ids: &[u64],
    max_polls: usize,
) -> usize {
    let mut polls_done = 0;
    let mut i = 0;

    while i < priority_queue.len() && polls_done < max_polls {
        let task = &mut priority_queue[i];

        if woken_ids.contains(&task.id) || task.poll_count == 0 {
            task.clear_woken();
            if task.poll() {
                priority_queue.remove(i);
                continue;
            }
            polls_done += 1;
        }
        i += 1;
    }

    priority_queue.retain(|task| !task.complete);

    polls_done
}

pub fn poll_critical_tasks() {
    let mut queue = ASYNC_QUEUE.lock();

    for task in queue.critical.iter_mut() {
        if !task.complete {
            task.poll();
        }
    }
    queue.critical.retain(|task| !task.complete);

    for task in queue.high.iter_mut() {
        if !task.complete {
            task.poll();
        }
    }
    queue.high.retain(|task| !task.complete);
}
