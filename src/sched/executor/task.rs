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

use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::Ordering;
use core::task::{Context, Poll};

use super::types::{AsyncTask, AsyncTaskPriority};
use super::state::{NEXT_TASK_ID, WOKEN_TASKS, EXECUTOR_STATS};
use super::waker::create_waker;

impl AsyncTask {
    pub fn new(
        name: &'static str,
        future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
        priority: AsyncTaskPriority,
    ) -> Self {
        let id = NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed);
        let now = crate::time::now_ns();
        Self {
            id,
            name,
            future,
            complete: false,
            priority,
            spawned_at_ns: now,
            last_poll_ns: 0,
            poll_count: 0,
        }
    }

    pub fn poll(&mut self) -> bool {
        if self.complete {
            return true;
        }

        EXECUTOR_STATS.polls_performed.fetch_add(1, Ordering::Relaxed);
        self.poll_count += 1;
        self.last_poll_ns = crate::time::now_ns();

        let waker = create_waker(self.id);
        let mut cx = Context::from_waker(&waker);

        match self.future.as_mut().poll(&mut cx) {
            Poll::Ready(()) => {
                self.complete = true;
                EXECUTOR_STATS.tasks_completed.fetch_add(1, Ordering::Relaxed);
                true
            }
            Poll::Pending => false,
        }
    }

    pub fn is_woken(&self) -> bool {
        WOKEN_TASKS.read().contains(&self.id)
    }

    pub fn clear_woken(&self) {
        let mut woken = WOKEN_TASKS.write();
        woken.retain(|&id| id != self.id);
    }
}
