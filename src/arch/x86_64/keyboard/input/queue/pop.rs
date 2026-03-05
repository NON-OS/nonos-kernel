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
use core::sync::atomic::Ordering;

use crate::arch::x86_64::keyboard::input::types::{EventFilter, EventPriority, InputEvent};
use super::state::INPUT_QUEUE;
use super::push::flush_pending_mouse_move;

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
