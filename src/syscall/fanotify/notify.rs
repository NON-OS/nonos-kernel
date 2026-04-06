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
use super::init::INSTANCES;

pub fn notify_access(path: &str) {
    notify_event(path, super::FAN_ACCESS);
}

pub fn notify_modify(path: &str) {
    notify_event(path, super::FAN_MODIFY);
}

pub fn notify_open(path: &str) {
    notify_event(path, super::FAN_OPEN);
}

pub fn notify_close_write(path: &str) {
    notify_event(path, super::FAN_CLOSE_WRITE);
}

pub fn notify_close_nowrite(path: &str) {
    notify_event(path, super::FAN_CLOSE_NOWRITE);
}

pub fn notify_create(path: &str) {
    notify_event(path, super::FAN_CREATE);
}

pub fn notify_delete(path: &str) {
    notify_event(path, super::FAN_DELETE);
}

pub fn notify_moved_from(path: &str) {
    notify_event(path, super::FAN_MOVED_FROM);
}

pub fn notify_moved_to(path: &str) {
    notify_event(path, super::FAN_MOVED_TO);
}

pub fn notify_attrib(path: &str) {
    notify_event(path, super::FAN_ATTRIB);
}

pub fn notify_event(path: &str, mask: u64) {
    let instances = INSTANCES.lock();
    for instance in instances.values() {
        let marks = instance.marks.lock();
        for mark in marks.iter() {
            if mark.matches(path, mask) {
                let pid = crate::process::current_pid().unwrap_or(0);
                let event = FanotifyEvent::new(mask, -1, pid);
                drop(marks);
                instance.queue_event(event);
                break;
            }
        }
    }
}

pub fn notify_event_with_fd(path: &str, mask: u64, fd: i32) {
    let instances = INSTANCES.lock();
    for instance in instances.values() {
        let marks = instance.marks.lock();
        for mark in marks.iter() {
            if mark.matches(path, mask) {
                let pid = crate::process::current_pid().unwrap_or(0);
                let event = FanotifyEvent::new(mask, fd, pid);
                drop(marks);
                instance.queue_event(event);
                break;
            }
        }
    }
}
