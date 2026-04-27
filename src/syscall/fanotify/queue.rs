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

use super::event::FanotifyEvent;
use super::fd::fd_to_instance;

pub fn queue_event(fd: i32, event: FanotifyEvent) -> Result<(), i32> {
    let instance = fd_to_instance(fd).ok_or(-9)?;
    instance.queue_event(event);
    Ok(())
}

pub fn queue_event_by_id(instance_id: u32, event: FanotifyEvent) -> Result<(), i32> {
    let instance = super::init::get_instance(instance_id).ok_or(-9)?;
    instance.queue_event(event);
    Ok(())
}

pub fn pending_events(fd: i32) -> usize {
    fd_to_instance(fd).map(|i| i.events.lock().len()).unwrap_or(0)
}

pub fn has_pending_events(fd: i32) -> bool {
    fd_to_instance(fd).map(|i| !i.events.lock().is_empty()).unwrap_or(false)
}

pub fn clear_events(fd: i32) -> Result<usize, i32> {
    let instance = fd_to_instance(fd).ok_or(-9)?;
    let mut events = instance.events.lock();
    let count = events.len();
    events.clear();
    Ok(count)
}

pub fn peek_event(fd: i32) -> Option<FanotifyEvent> {
    let instance = fd_to_instance(fd)?;
    let events = instance.events.lock();
    events.first().cloned()
}

pub fn pop_event(fd: i32) -> Option<FanotifyEvent> {
    let instance = fd_to_instance(fd)?;
    let mut events = instance.events.lock();
    if events.is_empty() {
        None
    } else {
        Some(events.remove(0))
    }
}

pub fn queue_capacity(fd: i32) -> usize {
    fd_to_instance(fd)
        .map(|i| if (i.flags & super::FAN_UNLIMITED_QUEUE) != 0 { 16384 } else { 256 })
        .unwrap_or(0)
}

pub fn queue_remaining(fd: i32) -> usize {
    fd_to_instance(fd)
        .map(|i| {
            let cap: usize = if (i.flags & super::FAN_UNLIMITED_QUEUE) != 0 { 16384 } else { 256 };
            cap.saturating_sub(i.events.lock().len())
        })
        .unwrap_or(0)
}

pub fn is_queue_full(fd: i32) -> bool {
    queue_remaining(fd) == 0
}

pub fn drain_events(fd: i32, max: usize) -> alloc::vec::Vec<FanotifyEvent> {
    fd_to_instance(fd)
        .map(|i| {
            let mut events = i.events.lock();
            let count = events.len().min(max);
            events.drain(0..count).collect()
        })
        .unwrap_or_else(alloc::vec::Vec::new)
}
