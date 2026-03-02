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

use super::types::{AsyncTask, AsyncTaskPriority};
use super::state::{ASYNC_QUEUE, EXECUTOR_STATS};
use super::waker::wake_task_internal;

pub fn spawn_async(name: &'static str, future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>) {
    spawn_async_with_priority(name, future, AsyncTaskPriority::Normal);
}

pub fn spawn_async_with_priority(
    name: &'static str,
    future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    priority: AsyncTaskPriority,
) {
    EXECUTOR_STATS.tasks_spawned.fetch_add(1, Ordering::Relaxed);
    let task = AsyncTask::new(name, future, priority);
    let task_id = task.id;
    ASYNC_QUEUE.lock().push(task);
    wake_task_internal(task_id);
}
