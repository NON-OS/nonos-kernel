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

use super::init::{FD_MAP, INSTANCES};

pub struct FanotifyStats {
    pub instance_count: usize,
    pub fd_count: usize,
    pub total_marks: usize,
    pub total_queued_events: usize,
    pub max_queue_size: usize,
}

pub fn get_stats() -> FanotifyStats {
    let instances = INSTANCES.lock();
    let mut total_marks = 0;
    let mut total_events = 0;
    let mut max_queue = 0;
    for inst in instances.values() {
        total_marks += inst.marks.lock().len();
        let events = inst.events.lock().len();
        total_events += events;
        if events > max_queue {
            max_queue = events;
        }
    }
    FanotifyStats {
        instance_count: instances.len(),
        fd_count: FD_MAP.lock().len(),
        total_marks,
        total_queued_events: total_events,
        max_queue_size: max_queue,
    }
}

pub fn instance_stats(fd: i32) -> Option<InstanceStats> {
    let instance = super::fd::fd_to_instance(fd)?;
    let id = instance.id;
    let flags = instance.flags;
    let event_f_flags = instance.event_f_flags;
    let mark_count = instance.marks.lock().len();
    let event_count = instance.events.lock().len();
    Some(InstanceStats { id, flags, event_f_flags, mark_count, event_count })
}

pub struct InstanceStats {
    pub id: u32,
    pub flags: u32,
    pub event_f_flags: u32,
    pub mark_count: usize,
    pub event_count: usize,
}

pub fn total_instances() -> usize {
    INSTANCES.lock().len()
}

pub fn total_fds() -> usize {
    FD_MAP.lock().len()
}

pub fn total_marks() -> usize {
    INSTANCES.lock().values().map(|i| i.marks.lock().len()).sum()
}

pub fn total_events() -> usize {
    INSTANCES.lock().values().map(|i| i.events.lock().len()).sum()
}

pub fn memory_usage() -> usize {
    let instances = INSTANCES.lock();
    let mut size = instances.len() * core::mem::size_of::<super::init::FanotifyInstance>();
    for inst in instances.values() {
        size += inst.marks.lock().len() * core::mem::size_of::<super::mark::FanotifyMark>();
        size += inst.events.lock().len() * core::mem::size_of::<super::event::FanotifyEvent>();
    }
    size
}
