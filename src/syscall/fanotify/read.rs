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
use super::event::FanotifyEventMetadata;
use super::fd::fd_to_instance;
use crate::usercopy::copy_to_user;
use alloc::vec;

pub fn fanotify_read(fd: i32, buf: u64, count: usize) -> Result<usize, i32> {
    let instance = fd_to_instance(fd).ok_or(-9i32)?;
    let mut events = instance.events.lock();
    if events.is_empty() {
        return Ok(0);
    }
    let meta_size = core::mem::size_of::<FanotifyEventMetadata>();
    let max_events = count / meta_size;
    if max_events == 0 {
        return Err(-22);
    }
    let mut buffer = vec![0u8; count];
    let mut written = 0usize;
    let mut event_count = 0usize;
    while !events.is_empty() && event_count < max_events {
        let event = events.remove(0);
        let metadata = event.to_metadata();
        let src = &metadata as *const _ as *const u8;
        unsafe {
            core::ptr::copy_nonoverlapping(src, buffer[written..].as_mut_ptr(), meta_size);
        }
        written += meta_size;
        event_count += 1;
    }
    if written > 0 {
        copy_to_user(buf, &buffer[..written]).map_err(|_| -14i32)?;
    }
    Ok(written)
}

pub fn fanotify_read_to_buffer(fd: i32, buffer: &mut [u8]) -> Result<usize, i32> {
    let instance = fd_to_instance(fd).ok_or(-9i32)?;
    let mut events = instance.events.lock();
    if events.is_empty() {
        return Ok(0);
    }
    let meta_size = core::mem::size_of::<FanotifyEventMetadata>();
    let max_events = buffer.len() / meta_size;
    if max_events == 0 {
        return Err(-22);
    }
    let mut written = 0usize;
    while !events.is_empty() && written + meta_size <= buffer.len() {
        let event = events.remove(0);
        let metadata = event.to_metadata();
        let src = &metadata as *const _ as *const u8;
        unsafe {
            core::ptr::copy_nonoverlapping(src, buffer[written..].as_mut_ptr(), meta_size);
        }
        written += meta_size;
    }
    Ok(written)
}

pub fn read_single_event(fd: i32) -> Result<FanotifyEventMetadata, i32> {
    let instance = fd_to_instance(fd).ok_or(-9i32)?;
    let mut events = instance.events.lock();
    if events.is_empty() {
        return Err(-11);
    }
    let event = events.remove(0);
    Ok(event.to_metadata())
}

pub fn can_read(fd: i32) -> bool {
    fd_to_instance(fd).map(|i| !i.events.lock().is_empty()).unwrap_or(false)
}

pub fn bytes_available(fd: i32) -> usize {
    let meta_size = core::mem::size_of::<FanotifyEventMetadata>();
    fd_to_instance(fd).map(|i| i.events.lock().len() * meta_size).unwrap_or(0)
}
