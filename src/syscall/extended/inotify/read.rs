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

extern crate alloc;
use super::instance::{FD_TO_INOTIFY, INOTIFY_INSTANCES};
use super::types::InotifyEvent;
use crate::usercopy::copy_to_user;
use alloc::vec;

pub fn inotify_read(fd: i32, buf: u64, count: usize) -> Result<usize, i32> {
    let id = FD_TO_INOTIFY.lock().get(&fd).copied().ok_or(-9i32)?;
    let mut instances = INOTIFY_INSTANCES.lock();
    let instance = instances.get_mut(&id).ok_or(-9i32)?;
    let mut buffer = vec![0u8; count];
    let written = instance.read_events(&mut buffer)?;
    if written > 0 {
        copy_to_user(buf, &buffer[..written]).map_err(|_| -14i32)?;
    }
    Ok(written)
}

pub fn inotify_read_to_buffer(fd: i32, buffer: &mut [u8]) -> Result<usize, i32> {
    let id = FD_TO_INOTIFY.lock().get(&fd).copied().ok_or(-9i32)?;
    let mut instances = INOTIFY_INSTANCES.lock();
    let instance = instances.get_mut(&id).ok_or(-9i32)?;
    instance.read_events(buffer)
}

pub fn can_read(fd: i32) -> bool {
    super::queue::has_pending_events(fd)
}

pub fn bytes_available(fd: i32) -> usize {
    let id = match FD_TO_INOTIFY.lock().get(&fd).copied() {
        Some(id) => id,
        None => return 0,
    };
    let instances = INOTIFY_INSTANCES.lock();
    let instance = match instances.get(&id) {
        Some(i) => i,
        None => return 0,
    };
    instance.events.iter().map(|e| e.event.total_size()).sum()
}

pub fn min_read_size() -> usize {
    core::mem::size_of::<InotifyEvent>()
}

pub fn read_single_event(fd: i32) -> Result<(i32, u32, u32, Option<alloc::string::String>), i32> {
    let id = FD_TO_INOTIFY.lock().get(&fd).copied().ok_or(-9i32)?;
    let mut instances = INOTIFY_INSTANCES.lock();
    let instance = instances.get_mut(&id).ok_or(-9i32)?;
    if instance.events.is_empty() {
        return Err(-11);
    }
    let event = instance.events.remove(0);
    Ok((event.event.wd, event.event.mask, event.event.cookie, event.name))
}

pub fn peek_next_event_size(fd: i32) -> Option<usize> {
    let id = FD_TO_INOTIFY.lock().get(&fd).copied()?;
    let instances = INOTIFY_INSTANCES.lock();
    let instance = instances.get(&id)?;
    instance.events.first().map(|e| e.event.total_size())
}

pub fn would_block(fd: i32) -> bool {
    let id = match FD_TO_INOTIFY.lock().get(&fd).copied() {
        Some(id) => id,
        None => return true,
    };
    let instances = INOTIFY_INSTANCES.lock();
    let instance = match instances.get(&id) {
        Some(i) => i,
        None => return true,
    };
    instance.events.is_empty() && instance.is_nonblock()
}
