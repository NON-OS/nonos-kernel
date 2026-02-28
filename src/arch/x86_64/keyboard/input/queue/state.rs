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
use core::sync::atomic::AtomicBool;
use spin::{Mutex, RwLock};

use crate::arch::x86_64::keyboard::input::types::{InputEvent, MouseMoveEvent};
use super::config::*;
use super::stats::QueueStatsAtomic;
use super::wait::WaitHandle;

pub(crate) struct InputQueueInner {
    pub events: VecDeque<InputEvent>,
    pub pending_mouse_move: Option<MouseMoveEvent>,
    pub coalesce_count: usize,
}

pub(crate) struct InputQueueState {
    pub inner: Mutex<InputQueueInner>,
    pub config: RwLock<QueueConfig>,
    pub stats: QueueStatsAtomic,
    pub shutdown: AtomicBool,
    pub waiters: Mutex<Vec<&'static WaitHandle>>,
}

pub(crate) static INPUT_QUEUE: InputQueueState = InputQueueState {
    inner: Mutex::new(InputQueueInner {
        events: VecDeque::new(),
        pending_mouse_move: None,
        coalesce_count: 0,
    }),
    config: RwLock::new(QueueConfig {
        max_size: DEFAULT_MAX_QUEUE_SIZE,
        pressure_threshold: DEFAULT_PRESSURE_THRESHOLD,
        coalesce_mouse_moves: true,
        max_coalesce_count: MAX_COALESCE_COUNT,
        drop_low_priority_under_pressure: true,
    }),
    stats: QueueStatsAtomic::new(),
    shutdown: AtomicBool::new(false),
    waiters: Mutex::new(Vec::new()),
};
