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

use super::instance::INOTIFY_INSTANCES;
use super::types::*;

pub fn notify_access(path: &str, name: Option<&str>) {
    notify_event(path, IN_ACCESS, name);
}

pub fn notify_modify(path: &str, name: Option<&str>) {
    notify_event(path, IN_MODIFY, name);
}

pub fn notify_attrib(path: &str, name: Option<&str>) {
    notify_event(path, IN_ATTRIB, name);
}

pub fn notify_close_write(path: &str, name: Option<&str>) {
    notify_event(path, IN_CLOSE_WRITE, name);
}

pub fn notify_close_nowrite(path: &str, name: Option<&str>) {
    notify_event(path, IN_CLOSE_NOWRITE, name);
}

pub fn notify_open(path: &str, name: Option<&str>) {
    notify_event(path, IN_OPEN, name);
}

pub fn notify_create(path: &str, name: Option<&str>) {
    notify_event(path, IN_CREATE, name);
}

pub fn notify_delete(path: &str, name: Option<&str>) {
    notify_event(path, IN_DELETE, name);
}

pub fn notify_delete_self(path: &str) {
    notify_event(path, IN_DELETE_SELF, None);
}

pub fn notify_move_self(path: &str) {
    notify_event(path, IN_MOVE_SELF, None);
}

pub fn notify_event(path: &str, mask: u32, name: Option<&str>) {
    let mut instances = INOTIFY_INSTANCES.lock();
    for instance in instances.values_mut() {
        let matching: alloc::vec::Vec<i32> = instance
            .watches
            .iter()
            .filter(|(_, watch)| (watch.mask & mask) != 0 && path_matches(&watch.path, path))
            .map(|(wd, _)| *wd)
            .collect();
        for wd in matching {
            instance.queue_event(wd, mask, name);
        }
    }
}

pub fn notify_move(from_path: &str, to_path: &str, from_name: Option<&str>, to_name: Option<&str>) {
    let mut instances = INOTIFY_INSTANCES.lock();
    for instance in instances.values_mut() {
        let mut from_wd = 0;
        let mut to_wd = 0;
        for (wd, watch) in instance.watches.iter() {
            if (watch.mask & IN_MOVED_FROM) != 0 && path_matches(&watch.path, from_path) {
                from_wd = *wd;
            }
            if (watch.mask & IN_MOVED_TO) != 0 && path_matches(&watch.path, to_path) {
                to_wd = *wd;
            }
        }
        if from_wd != 0 || to_wd != 0 {
            instance.queue_move_event(from_wd, to_wd, from_name, to_name);
        }
    }
}

fn path_matches(watch_path: &str, event_path: &str) -> bool {
    event_path.starts_with(watch_path) || watch_path == event_path
}

pub fn notify_unmount(path: &str) {
    notify_event(path, IN_UNMOUNT, None);
}

pub fn notify_isdir(path: &str, mask: u32, name: Option<&str>) {
    notify_event(path, mask | IN_ISDIR, name);
}
