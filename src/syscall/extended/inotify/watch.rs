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

use super::instance::{FD_TO_INOTIFY, INOTIFY_INSTANCES};
use alloc::string::String;
use alloc::vec::Vec;

pub fn add_watch(fd: i32, path: &str, mask: u32) -> Result<i32, i32> {
    let id = FD_TO_INOTIFY.lock().get(&fd).copied().ok_or(-9i32)?;
    let mut instances = INOTIFY_INSTANCES.lock();
    let instance = instances.get_mut(&id).ok_or(-9i32)?;
    instance.add_watch(path, mask)
}

pub fn remove_watch(fd: i32, wd: i32) -> Result<(), i32> {
    let id = FD_TO_INOTIFY.lock().get(&fd).copied().ok_or(-9i32)?;
    let mut instances = INOTIFY_INSTANCES.lock();
    let instance = instances.get_mut(&id).ok_or(-9i32)?;
    instance.rm_watch(wd)
}

pub fn get_watch_path(fd: i32, wd: i32) -> Option<String> {
    let id = FD_TO_INOTIFY.lock().get(&fd).copied()?;
    let instances = INOTIFY_INSTANCES.lock();
    let instance = instances.get(&id)?;
    instance.watches.get(&wd).map(|w| w.path.clone())
}

pub fn get_watch_mask(fd: i32, wd: i32) -> Option<u32> {
    let id = FD_TO_INOTIFY.lock().get(&fd).copied()?;
    let instances = INOTIFY_INSTANCES.lock();
    let instance = instances.get(&id)?;
    instance.watches.get(&wd).map(|w| w.mask)
}

pub fn watch_count(fd: i32) -> usize {
    let id = match FD_TO_INOTIFY.lock().get(&fd).copied() {
        Some(id) => id,
        None => return 0,
    };
    let instances = INOTIFY_INSTANCES.lock();
    instances.get(&id).map(|i| i.watches.len()).unwrap_or(0)
}

pub fn all_watches(fd: i32) -> Vec<(i32, String, u32)> {
    let id = match FD_TO_INOTIFY.lock().get(&fd).copied() {
        Some(id) => id,
        None => return Vec::new(),
    };
    let instances = INOTIFY_INSTANCES.lock();
    let instance = match instances.get(&id) {
        Some(i) => i,
        None => return Vec::new(),
    };
    instance.watches.values().map(|w| (w.wd, w.path.clone(), w.mask)).collect()
}

pub fn find_watch_by_path(fd: i32, path: &str) -> Option<i32> {
    let id = FD_TO_INOTIFY.lock().get(&fd).copied()?;
    let instances = INOTIFY_INSTANCES.lock();
    let instance = instances.get(&id)?;
    instance.path_to_wd.get(path).copied()
}

pub fn is_oneshot(fd: i32, wd: i32) -> bool {
    let id = match FD_TO_INOTIFY.lock().get(&fd).copied() {
        Some(id) => id,
        None => return false,
    };
    let instances = INOTIFY_INSTANCES.lock();
    let instance = match instances.get(&id) {
        Some(i) => i,
        None => return false,
    };
    instance.watches.get(&wd).map(|w| w.oneshot).unwrap_or(false)
}

pub fn modify_watch_mask(fd: i32, wd: i32, new_mask: u32) -> Result<(), i32> {
    let id = FD_TO_INOTIFY.lock().get(&fd).copied().ok_or(-9i32)?;
    let mut instances = INOTIFY_INSTANCES.lock();
    let instance = instances.get_mut(&id).ok_or(-9i32)?;
    let watch = instance.watches.get_mut(&wd).ok_or(-22i32)?;
    watch.mask = new_mask & super::types::IN_ALL_EVENTS;
    Ok(())
}

pub fn total_watches() -> usize {
    INOTIFY_INSTANCES.lock().values().map(|i| i.watches.len()).sum()
}
