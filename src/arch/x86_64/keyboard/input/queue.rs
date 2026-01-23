// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, RwLock};

use super::error::{InputError, InputErrorCode, InputResult};
use super::types::{
    DeviceId, EventFilter, EventPriority, InputEvent, InputEventKind, MouseMoveEvent,
};

pub const DEFAULT_MAX_QUEUE_SIZE: usize = 256;
pub const MAX_ALLOWED_QUEUE_SIZE: usize = 65536;
pub const DEFAULT_PRESSURE_THRESHOLD: usize = 192;
pub const MAX_COALESCE_COUNT: usize = 16;

#[derive(Debug, Clone)]
pub struct QueueConfig {
    pub max_size: usize,
    pub pressure_threshold: usize,
    pub coalesce_mouse_moves: bool,
    pub max_coalesce_count: usize,
    pub drop_low_priority_under_pressure: bool,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_size: DEFAULT_MAX_QUEUE_SIZE,
            pressure_threshold: DEFAULT_PRESSURE_THRESHOLD,
            coalesce_mouse_moves: true,
            max_coalesce_count: MAX_COALESCE_COUNT,
            drop_low_priority_under_pressure: true,
        }
    }
}

impl QueueConfig {
    pub fn validate(&self) -> InputResult<()> {
        if self.max_size == 0 {
            return Err(InputError::with_context(
                InputErrorCode::InvalidConfig,
                "max_size cannot be zero",
            ));
        }
        if self.max_size > MAX_ALLOWED_QUEUE_SIZE {
            return Err(InputError::with_context(
                InputErrorCode::InvalidConfig,
                alloc::format!("max_size exceeds limit of {}", MAX_ALLOWED_QUEUE_SIZE),
            ));
        }
        if self.pressure_threshold >= self.max_size {
            return Err(InputError::with_context(
                InputErrorCode::InvalidConfig,
                "pressure_threshold must be less than max_size",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct QueueStats {
    pub total_events: u64,
    pub dropped_events: u64,
    pub priority_drops: u64,
    pub coalesced_events: u64,
    pub peak_size: usize,
    pub current_size: usize,
    pub pressure_warnings: u64,
}

pub struct WaitHandle {
    notified: AtomicBool,
}

impl WaitHandle {
    pub const fn new() -> Self {
        Self {
            notified: AtomicBool::new(false),
        }
    }

    pub fn is_notified(&self) -> bool {
        self.notified.load(Ordering::Acquire)
    }

    pub fn clear(&self) {
        self.notified.store(false, Ordering::Release);
    }

    pub(super) fn notify(&self) {
        self.notified.store(true, Ordering::Release);
    }
}

impl Default for WaitHandle {
    fn default() -> Self {
        Self::new()
    }
}

struct InputQueueInner {
    events: VecDeque<InputEvent>,
    pending_mouse_move: Option<MouseMoveEvent>,
    coalesce_count: usize,
}

struct QueueStatsAtomic {
    total_events: AtomicU64,
    dropped_events: AtomicU64,
    priority_drops: AtomicU64,
    coalesced_events: AtomicU64,
    peak_size: AtomicUsize,
    pressure_warnings: AtomicU64,
}

impl QueueStatsAtomic {
    const fn new() -> Self {
        Self {
            total_events: AtomicU64::new(0),
            dropped_events: AtomicU64::new(0),
            priority_drops: AtomicU64::new(0),
            coalesced_events: AtomicU64::new(0),
            peak_size: AtomicUsize::new(0),
            pressure_warnings: AtomicU64::new(0),
        }
    }

    fn snapshot(&self, current_size: usize) -> QueueStats {
        QueueStats {
            total_events: self.total_events.load(Ordering::Relaxed),
            dropped_events: self.dropped_events.load(Ordering::Relaxed),
            priority_drops: self.priority_drops.load(Ordering::Relaxed),
            coalesced_events: self.coalesced_events.load(Ordering::Relaxed),
            peak_size: self.peak_size.load(Ordering::Relaxed),
            current_size,
            pressure_warnings: self.pressure_warnings.load(Ordering::Relaxed),
        }
    }
}

pub(super) struct InputQueueState {
    pub inner: Mutex<InputQueueInner>,
    pub config: RwLock<QueueConfig>,
    pub stats: QueueStatsAtomic,
    pub shutdown: AtomicBool,
    pub waiters: Mutex<Vec<&'static WaitHandle>>,
}

pub(super) static INPUT_QUEUE: InputQueueState = InputQueueState {
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

pub fn configure(config: QueueConfig) -> InputResult<()> {
    config.validate()?;
    *INPUT_QUEUE.config.write() = config;
    Ok(())
}

pub fn get_config() -> QueueConfig {
    INPUT_QUEUE.config.read().clone()
}

pub fn push_event(event: InputEvent) -> InputResult<()> {
    if INPUT_QUEUE.shutdown.load(Ordering::Acquire) {
        return Err(InputError::new(InputErrorCode::QueueShutdown));
    }

    let config = INPUT_QUEUE.config.read();
    let mut inner = INPUT_QUEUE.inner.lock();

    if config.coalesce_mouse_moves {
        if let InputEventKind::MouseMove(move_event) = &event.kind {
            if let Some(ref mut pending) = inner.pending_mouse_move {
                pending.dx = pending.dx.saturating_add(move_event.dx);
                pending.dy = pending.dy.saturating_add(move_event.dy);
                if move_event.abs_x.is_some() {
                    pending.abs_x = move_event.abs_x;
                }
                if move_event.abs_y.is_some() {
                    pending.abs_y = move_event.abs_y;
                }
                inner.coalesce_count += 1;
                INPUT_QUEUE
                    .stats
                    .coalesced_events
                    .fetch_add(1, Ordering::Relaxed);

                if inner.coalesce_count >= config.max_coalesce_count {
                    flush_pending_mouse_move(&mut inner, &config)?;
                }

                return Ok(());
            } else {
                inner.pending_mouse_move = Some(*move_event);
                inner.coalesce_count = 1;
                INPUT_QUEUE.stats.total_events.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        } else if inner.pending_mouse_move.is_some() {
            flush_pending_mouse_move(&mut inner, &config)?;
        }
    }

    push_event_inner(&mut inner, &config, event)
}

fn flush_pending_mouse_move(
    inner: &mut InputQueueInner,
    config: &QueueConfig,
) -> InputResult<()> {
    if let Some(pending) = inner.pending_mouse_move.take() {
        let event = InputEvent::new(InputEventKind::MouseMove(pending))
            .with_device(DeviceId::MOUSE);
        inner.coalesce_count = 0;
        push_event_inner(inner, config, event)?;
    }
    Ok(())
}

fn push_event_inner(
    inner: &mut InputQueueInner,
    config: &QueueConfig,
    event: InputEvent,
) -> InputResult<()> {
    let current_len = inner.events.len();

    if current_len >= config.pressure_threshold {
        INPUT_QUEUE
            .stats
            .pressure_warnings
            .fetch_add(1, Ordering::Relaxed);

        if config.drop_low_priority_under_pressure && event.priority == EventPriority::Low {
            INPUT_QUEUE
                .stats
                .priority_drops
                .fetch_add(1, Ordering::Relaxed);
            return Err(InputError::new(InputErrorCode::FilterRejected)
                .with_event_type(event.kind.type_name()));
        }
    }

    if current_len >= config.max_size {
        if config.drop_low_priority_under_pressure {
            if let Some(idx) = inner
                .events
                .iter()
                .position(|e| e.priority == EventPriority::Low)
            {
                inner.events.remove(idx);
                INPUT_QUEUE
                    .stats
                    .priority_drops
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                inner.events.pop_front();
                INPUT_QUEUE
                    .stats
                    .dropped_events
                    .fetch_add(1, Ordering::Relaxed);
            }
        } else {
            inner.events.pop_front();
            INPUT_QUEUE
                .stats
                .dropped_events
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    inner.events.push_back(event);
    INPUT_QUEUE.stats.total_events.fetch_add(1, Ordering::Relaxed);

    let new_len = inner.events.len();
    let mut peak = INPUT_QUEUE.stats.peak_size.load(Ordering::Relaxed);
    while new_len > peak {
        match INPUT_QUEUE.stats.peak_size.compare_exchange_weak(
            peak,
            new_len,
            Ordering::Release,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(p) => peak = p,
        }
    }

    notify_waiters();

    Ok(())
}

pub fn pop_event() -> Option<InputEvent> {
    pop_event_filtered(&EventFilter::all())
}

pub fn pop_event_filtered(filter: &EventFilter) -> Option<InputEvent> {
    if INPUT_QUEUE.shutdown.load(Ordering::Acquire) {
        return None;
    }

    let config = INPUT_QUEUE.config.read();
    let mut inner = INPUT_QUEUE.inner.lock();

    if filter.mouse && inner.pending_mouse_move.is_some() {
        let _ = flush_pending_mouse_move(&mut inner, &config);
    }

    if let Some(idx) = inner.events.iter().position(|e| filter.matches(e)) {
        inner.events.remove(idx)
    } else {
        None
    }
}

pub fn peek_event() -> Option<InputEvent> {
    peek_event_filtered(&EventFilter::all())
}

pub fn peek_event_filtered(filter: &EventFilter) -> Option<InputEvent> {
    if INPUT_QUEUE.shutdown.load(Ordering::Acquire) {
        return None;
    }

    let inner = INPUT_QUEUE.inner.lock();
    inner.events.iter().find(|e| filter.matches(e)).copied()
}

pub fn drain_events() -> Vec<InputEvent> {
    drain_events_filtered(&EventFilter::all())
}

pub fn drain_events_filtered(filter: &EventFilter) -> Vec<InputEvent> {
    if INPUT_QUEUE.shutdown.load(Ordering::Acquire) {
        return Vec::new();
    }

    let config = INPUT_QUEUE.config.read();
    let mut inner = INPUT_QUEUE.inner.lock();

    if filter.mouse && inner.pending_mouse_move.is_some() {
        let _ = flush_pending_mouse_move(&mut inner, &config);
    }

    if filter.keyboard && filter.mouse && filter.device && filter.min_priority == EventPriority::Low
    {
        inner.events.drain(..).collect()
    } else {
        let mut result = Vec::new();
        let mut i = 0;
        while i < inner.events.len() {
            if filter.matches(&inner.events[i]) {
                if let Some(event) = inner.events.remove(i) {
                    result.push(event);
                }
            } else {
                i += 1;
            }
        }
        result
    }
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

pub fn register_waiter(handle: &'static WaitHandle) {
    INPUT_QUEUE.waiters.lock().push(handle);
}

pub fn unregister_waiter(handle: &'static WaitHandle) {
    let mut waiters = INPUT_QUEUE.waiters.lock();
    waiters.retain(|h| !core::ptr::eq(*h, handle));
}

fn notify_waiters() {
    let waiters = INPUT_QUEUE.waiters.lock();
    for waiter in waiters.iter() {
        waiter.notify();
    }
}
