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

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::types::{
    InotifyStats, IN_ISDIR, IN_MOVED_FROM, IN_MOVED_TO, EBADF,
};
use super::instance::{
    INOTIFY_INSTANCES, FD_TO_INOTIFY, NEXT_FD,
};

pub fn allocate_fd() -> i32 {
    NEXT_FD.fetch_add(1, Ordering::SeqCst) as i32
}

pub fn inotify_read(fd: i32, buf: *mut u8, count: usize) -> Result<usize, i32> {
    let inotify_id = match FD_TO_INOTIFY.lock().get(&fd) {
        Some(&id) => id,
        None => return Err(EBADF),
    };

    let mut instances = INOTIFY_INSTANCES.lock();
    let instance = match instances.get_mut(&inotify_id) {
        Some(inst) => inst,
        None => return Err(EBADF),
    };

    let buffer = unsafe { core::slice::from_raw_parts_mut(buf, count) };
    instance.read_events(buffer)
}

pub fn inotify_close(fd: i32) -> Result<(), i32> {
    let inotify_id = match FD_TO_INOTIFY.lock().remove(&fd) {
        Some(id) => id,
        None => return Err(EBADF),
    };

    INOTIFY_INSTANCES.lock().remove(&inotify_id);
    Ok(())
}

pub fn notify_event(path: &str, mask: u32, name: Option<&str>) {
    let mut instances = INOTIFY_INSTANCES.lock();

    for instance in instances.values_mut() {
        let matching_watches: Vec<(i32, u32)> = instance
            .watches
            .values()
            .filter(|watch| watch_matches(&watch.path, path) && (watch.mask & mask) != 0)
            .map(|watch| (watch.wd, mask))
            .collect();

        for (wd, event_mask) in matching_watches {
            let mut final_mask = event_mask;
            if is_directory(path) {
                final_mask |= IN_ISDIR;
            }
            instance.queue_event(wd, final_mask, name);
        }
    }
}

pub fn notify_move(from_path: &str, to_path: &str, name: Option<&str>) {
    let mut instances = INOTIFY_INSTANCES.lock();

    for instance in instances.values_mut() {
        let mut from_wd = 0i32;
        let mut to_wd = 0i32;

        for watch in instance.watches.values() {
            if watch_matches(&watch.path, from_path) && (watch.mask & IN_MOVED_FROM) != 0 {
                from_wd = watch.wd;
            }
            if watch_matches(&watch.path, to_path) && (watch.mask & IN_MOVED_TO) != 0 {
                to_wd = watch.wd;
            }
        }

        if from_wd != 0 || to_wd != 0 {
            instance.queue_move_event(from_wd, to_wd, name, name);
        }
    }
}

pub fn inotify_has_events(fd: i32) -> bool {
    let inotify_id = match FD_TO_INOTIFY.lock().get(&fd) {
        Some(&id) => id,
        None => return false,
    };

    let instances = INOTIFY_INSTANCES.lock();
    instances.get(&inotify_id)
        .map(|inst| inst.has_events())
        .unwrap_or(false)
}

pub fn is_inotify(fd: i32) -> bool {
    FD_TO_INOTIFY.lock().contains_key(&fd)
}

pub fn fd_to_inotify_id(fd: i32) -> Option<u32> {
    FD_TO_INOTIFY.lock().get(&fd).copied()
}

pub fn watch_matches(watch_path: &str, event_path: &str) -> bool {
    if watch_path == event_path {
        return true;
    }

    if event_path.starts_with(watch_path) {
        let suffix = &event_path[watch_path.len()..];
        if suffix.starts_with('/') && !suffix[1..].contains('/') {
            return true;
        }
    }

    false
}

pub fn path_exists(path: &str) -> bool {
    crate::fs::ramfs::file_exists(path) || crate::fs::ramfs::dir_exists(path)
}

pub fn is_directory(path: &str) -> bool {
    crate::fs::ramfs::dir_exists(path)
}

pub fn get_inotify_stats() -> InotifyStats {
    let instances = INOTIFY_INSTANCES.lock();
    let mut total_watches = 0;
    let mut total_events = 0;

    for inst in instances.values() {
        total_watches += inst.watches.len();
        total_events += inst.events.len();
    }

    InotifyStats {
        instance_count: instances.len(),
        total_watches,
        total_queued_events: total_events,
    }
}
