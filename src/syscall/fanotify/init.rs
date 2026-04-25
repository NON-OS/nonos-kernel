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
use super::event::FanotifyEvent;
use super::mark::FanotifyMark;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use spin::Mutex;

pub struct FanotifyInstance {
    pub id: u32,
    pub flags: u32,
    pub event_f_flags: u32,
    pub marks: Mutex<Vec<FanotifyMark>>,
    pub events: Mutex<Vec<FanotifyEvent>>,
}

pub static INSTANCES: Mutex<BTreeMap<u32, Arc<FanotifyInstance>>> = Mutex::new(BTreeMap::new());
pub static FD_MAP: Mutex<BTreeMap<i32, u32>> = Mutex::new(BTreeMap::new());
pub static FD_OWNER: Mutex<BTreeMap<i32, u32>> = Mutex::new(BTreeMap::new());
pub static NEXT_ID: AtomicU32 = AtomicU32::new(1);
pub static NEXT_FD: AtomicI32 = AtomicI32::new(0x8000_0000u32 as i32);

impl FanotifyInstance {
    pub fn new(flags: u32, event_f_flags: u32) -> Arc<Self> {
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let inst = Arc::new(Self {
            id,
            flags,
            event_f_flags,
            marks: Mutex::new(Vec::new()),
            events: Mutex::new(Vec::new()),
        });
        INSTANCES.lock().insert(id, inst.clone());
        inst
    }

    pub fn queue_event(&self, event: FanotifyEvent) {
        let mut events = self.events.lock();
        let limit = if (self.flags & super::FAN_UNLIMITED_QUEUE) != 0 { 16384 } else { 256 };
        if events.len() < limit {
            events.push(event);
        }
    }

    pub fn has_events(&self) -> bool {
        !self.events.lock().is_empty()
    }
}

pub fn get_instance(id: u32) -> Option<Arc<FanotifyInstance>> {
    INSTANCES.lock().get(&id).cloned()
}
pub fn remove_instance(id: u32) {
    INSTANCES.lock().remove(&id);
}
pub fn get_by_fd(fd: i32) -> Option<Arc<FanotifyInstance>> {
    let id = FD_MAP.lock().get(&fd).copied()?;
    get_instance(id)
}
pub fn is_fanotify_fd(fd: i32) -> bool {
    FD_MAP.lock().contains_key(&fd)
}

pub fn sys_fanotify_init(flags: u32, event_f_flags: u32) -> i64 {
    let valid = super::FAN_CLOEXEC
        | super::FAN_NONBLOCK
        | super::FAN_CLASS_NOTIF
        | super::FAN_CLASS_CONTENT
        | super::FAN_CLASS_PRE_CONTENT
        | super::FAN_UNLIMITED_QUEUE
        | super::FAN_UNLIMITED_MARKS
        | super::FAN_REPORT_TID
        | super::FAN_REPORT_FID;
    if (flags & !valid) != 0 {
        return -22;
    }
    let instance = FanotifyInstance::new(flags, event_f_flags);
    let fd = NEXT_FD.fetch_add(1, Ordering::SeqCst);
    FD_MAP.lock().insert(fd, instance.id);
    let pid = crate::process::current_pid().unwrap_or(0);
    FD_OWNER.lock().insert(fd, pid);
    fd as i64
}
