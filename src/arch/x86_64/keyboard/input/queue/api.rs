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

use core::sync::atomic::Ordering;

use crate::arch::x86_64::keyboard::input::error::InputResult;
use super::config::QueueConfig;
use super::stats::QueueStats;
use super::wait::WaitHandle;
use super::state::INPUT_QUEUE;

pub fn configure(config: QueueConfig) -> InputResult<()> {
    config.validate()?;
    *INPUT_QUEUE.config.write() = config;
    Ok(())
}

pub fn get_config() -> QueueConfig {
    INPUT_QUEUE.config.read().clone()
}

pub fn queue_len() -> usize {
    let inner = INPUT_QUEUE.inner.lock();
    inner.events.len() + if inner.pending_mouse_move.is_some() { 1 } else { 0 }
}

pub fn is_empty() -> bool {
    let inner = INPUT_QUEUE.inner.lock();
    inner.events.is_empty() && inner.pending_mouse_move.is_none()
}

pub fn clear() {
    let mut inner = INPUT_QUEUE.inner.lock();
    inner.events.clear();
    inner.pending_mouse_move = None;
    inner.coalesce_count = 0;
}

pub fn stats() -> QueueStats {
    let inner = INPUT_QUEUE.inner.lock();
    let current_size = inner.events.len();
    INPUT_QUEUE.stats.snapshot(current_size)
}

pub fn total_events() -> u64 {
    INPUT_QUEUE.stats.total_events.load(Ordering::Relaxed)
}

pub fn dropped_events() -> u64 {
    INPUT_QUEUE.stats.dropped_events.load(Ordering::Relaxed)
}

pub fn shutdown() {
    INPUT_QUEUE.shutdown.store(true, Ordering::Release);
    notify_waiters();
}

pub fn restart() {
    INPUT_QUEUE.shutdown.store(false, Ordering::Release);
}

pub fn is_shutdown() -> bool {
    INPUT_QUEUE.shutdown.load(Ordering::Acquire)
}

pub fn queue_pressure() -> u8 {
    super::queue_pressure_inner()
}

pub fn register_waiter(handle: &'static WaitHandle) {
    INPUT_QUEUE.waiters.lock().push(handle);
}

pub fn unregister_waiter(handle: &'static WaitHandle) {
    let mut waiters = INPUT_QUEUE.waiters.lock();
    waiters.retain(|h| !core::ptr::eq(*h, handle));
}

pub(crate) fn notify_waiters() {
    let waiters = INPUT_QUEUE.waiters.lock();
    for waiter in waiters.iter() {
        waiter.notify();
    }
}
