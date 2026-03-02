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

use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;
use spin::{Mutex, RwLock};

use super::types::ExecutorStats;
use super::queue::PriorityTaskQueue;

pub(super) static NEXT_TASK_ID: AtomicU64 = AtomicU64::new(1);
pub(super) static WOKEN_TASKS: RwLock<Vec<u64>> = RwLock::new(Vec::new());
pub(super) static EXECUTOR_STATS: ExecutorStats = ExecutorStats::new();
pub(super) static ASYNC_QUEUE: Mutex<PriorityTaskQueue> = Mutex::new(PriorityTaskQueue::new());
