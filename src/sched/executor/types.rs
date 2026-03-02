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
use core::sync::atomic::{AtomicBool, AtomicU64};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AsyncTaskPriority {
    Critical = 0,
    High = 1,
    Normal = 2,
    Low = 3,
    Idle = 4,
}

impl Default for AsyncTaskPriority {
    fn default() -> Self {
        AsyncTaskPriority::Normal
    }
}

pub struct AsyncTask {
    pub id: u64,
    pub name: &'static str,
    pub future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    pub complete: bool,
    pub priority: AsyncTaskPriority,
    pub spawned_at_ns: u64,
    pub last_poll_ns: u64,
    pub poll_count: u64,
}

pub(super) struct ExecutorStats {
    pub tasks_spawned: AtomicU64,
    pub tasks_completed: AtomicU64,
    pub polls_performed: AtomicU64,
    pub wakeups_triggered: AtomicU64,
}

impl ExecutorStats {
    pub const fn new() -> Self {
        Self {
            tasks_spawned: AtomicU64::new(0),
            tasks_completed: AtomicU64::new(0),
            polls_performed: AtomicU64::new(0),
            wakeups_triggered: AtomicU64::new(0),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExecutorStatsSnapshot {
    pub tasks_spawned: u64,
    pub tasks_completed: u64,
    pub polls_performed: u64,
    pub wakeups_triggered: u64,
    pub pending_tasks: usize,
    pub woken_tasks: usize,
}

#[repr(C)]
pub(super) struct WakerData {
    pub task_id: u64,
    pub woken: AtomicBool,
}
