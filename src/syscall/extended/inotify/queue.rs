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

use super::instance::{QueuedEvent, FD_TO_INOTIFY, INOTIFY_INSTANCES};
use super::types::MAX_QUEUED_EVENTS;
use alloc::vec::Vec;

pub fn queue_event(fd: i32, wd: i32, mask: u32, name: Option<&str>) -> Result<(), i32> {
    let id = FD_TO_INOTIFY.lock().get(&fd).copied().ok_or(-9i32)?;
    let mut instances = INOTIFY_INSTANCES.lock();
    let instance = instances.get_mut(&id).ok_or(-9i32)?;
    instance.queue_event(wd, mask, name);
    Ok(())
}

pub fn queue_event_by_id(
    instance_id: u32,
    wd: i32,
    mask: u32,
    name: Option<&str>,
) -> Result<(), i32> {
    let mut instances = INOTIFY_INSTANCES.lock();
    let instance = instances.get_mut(&instance_id).ok_or(-9i32)?;
    instance.queue_event(wd, mask, name);
    Ok(())
}

pub fn pending_events(fd: i32) -> usize {
    let id = match FD_TO_INOTIFY.lock().get(&fd).copied() {
        Some(id) => id,
        None => return 0,
    };
    let instances = INOTIFY_INSTANCES.lock();
    instances.get(&id).map(|i| i.events.len()).unwrap_or(0)
}

pub fn has_pending_events(fd: i32) -> bool {
    let id = match FD_TO_INOTIFY.lock().get(&fd).copied() {
        Some(id) => id,
        None => return false,
    };
    let instances = INOTIFY_INSTANCES.lock();
    instances.get(&id).map(|i| !i.events.is_empty()).unwrap_or(false)
}

pub fn clear_events(fd: i32) -> Result<usize, i32> {
    let id = FD_TO_INOTIFY.lock().get(&fd).copied().ok_or(-9i32)?;
    let mut instances = INOTIFY_INSTANCES.lock();
    let instance = instances.get_mut(&id).ok_or(-9i32)?;
    let count = instance.events.len();
    instance.events.clear();
    Ok(count)
}

pub fn peek_event(fd: i32) -> Option<(i32, u32, u32)> {
    let id = FD_TO_INOTIFY.lock().get(&fd).copied()?;
    let instances = INOTIFY_INSTANCES.lock();
    let instance = instances.get(&id)?;
    instance.events.first().map(|e| (e.event.wd, e.event.mask, e.event.cookie))
}

pub fn queue_capacity() -> usize {
    MAX_QUEUED_EVENTS
}

pub fn queue_remaining(fd: i32) -> usize {
    let pending = pending_events(fd);
    MAX_QUEUED_EVENTS.saturating_sub(pending)
}

pub fn is_queue_full(fd: i32) -> bool {
    pending_events(fd) >= MAX_QUEUED_EVENTS
}

pub fn drain_events(fd: i32, max: usize) -> Vec<QueuedEvent> {
    let id = match FD_TO_INOTIFY.lock().get(&fd).copied() {
        Some(id) => id,
        None => return Vec::new(),
    };
    let mut instances = INOTIFY_INSTANCES.lock();
    let instance = match instances.get_mut(&id) {
        Some(i) => i,
        None => return Vec::new(),
    };
    let count = instance.events.len().min(max);
    instance.events.drain(0..count).collect()
}

pub fn total_queued_events() -> usize {
    INOTIFY_INSTANCES.lock().values().map(|i| i.events.len()).sum()
}

pub fn queue_move_event(
    fd: i32,
    from_wd: i32,
    to_wd: i32,
    from_name: Option<&str>,
    to_name: Option<&str>,
) -> Result<(), i32> {
    let id = FD_TO_INOTIFY.lock().get(&fd).copied().ok_or(-9i32)?;
    let mut instances = INOTIFY_INSTANCES.lock();
    let instance = instances.get_mut(&id).ok_or(-9i32)?;
    instance.queue_move_event(from_wd, to_wd, from_name, to_name);
    Ok(())
}
