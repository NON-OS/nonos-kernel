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
use super::init::get_by_fd;
use super::init::{FD_MAP, INSTANCES};
use crate::usercopy::copy_to_user;
use alloc::vec;

pub fn is_fanotify(fd: i32) -> bool {
    FD_MAP.lock().contains_key(&fd)
}

pub fn fd_to_fanotify_id(fd: i32) -> Option<u32> {
    FD_MAP.lock().get(&fd).copied()
}

pub fn fanotify_read(fd: i32, buf: u64, count: usize) -> Result<usize, i32> {
    let instance = get_by_fd(fd).ok_or(-9i32)?;
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

pub fn fanotify_close(fd: i32) -> Result<(), i32> {
    let id = FD_MAP.lock().remove(&fd).ok_or(-9i32)?;
    INSTANCES.lock().remove(&id);
    Ok(())
}

pub fn fanotify_has_events(fd: i32) -> bool {
    get_by_fd(fd).map(|i| i.has_events()).unwrap_or(false)
}

pub fn notify_fs_event(path: &str, mask: u64) {
    let instances = INSTANCES.lock();
    for instance in instances.values() {
        let marks = instance.marks.lock();
        for mark in marks.iter() {
            if mark.matches(path, mask) {
                let pid = crate::process::current_pid().unwrap_or(0);
                let event = super::event::FanotifyEvent::new(mask, -1, pid);
                drop(marks);
                instance.queue_event(event);
                break;
            }
        }
    }
}

pub struct FanotifyStats {
    pub instance_count: usize,
    pub total_marks: usize,
    pub total_queued_events: usize,
}

pub fn get_fanotify_stats() -> FanotifyStats {
    let instances = INSTANCES.lock();
    let mut total_marks = 0;
    let mut total_events = 0;
    for inst in instances.values() {
        total_marks += inst.marks.lock().len();
        total_events += inst.events.lock().len();
    }
    FanotifyStats {
        instance_count: instances.len(),
        total_marks,
        total_queued_events: total_events,
    }
}
