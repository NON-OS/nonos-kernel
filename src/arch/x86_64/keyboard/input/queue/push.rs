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

use crate::arch::x86_64::keyboard::input::error::{InputError, InputErrorCode, InputResult};
use crate::arch::x86_64::keyboard::input::types::{DeviceId, EventPriority, InputEvent, InputEventKind};
use super::config::QueueConfig;
use super::state::{INPUT_QUEUE, InputQueueInner};
use super::api::notify_waiters;

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

pub(crate) fn flush_pending_mouse_move(
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

pub(crate) fn push_event_inner(
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
