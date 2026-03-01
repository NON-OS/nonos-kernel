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

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicI32, Ordering};
use spin::Mutex;

use super::types::{
    InotifyEvent, IN_NONBLOCK, IN_ALL_EVENTS, IN_MASK_CREATE, IN_MASK_ADD,
    IN_ONESHOT, IN_ONLYDIR, IN_IGNORED, IN_Q_OVERFLOW, IN_MOVED_FROM, IN_MOVED_TO,
    EINVAL, ENOMEM, ENOENT, ENOTDIR, EEXIST, EAGAIN,
    MAX_WATCHES_PER_INSTANCE, MAX_QUEUED_EVENTS,
};
use super::util::{path_exists, is_directory};

#[derive(Clone)]
pub struct QueuedEvent {
    pub event: InotifyEvent,
    pub name: Option<String>,
}

impl QueuedEvent {
    pub fn new(wd: i32, mask: u32, cookie: u32, name: Option<&str>) -> Self {
        Self {
            event: InotifyEvent::new(wd, mask, cookie, name),
            name: name.map(String::from),
        }
    }

    pub fn write_to(&self, buf: &mut [u8]) -> Option<usize> {
        let total_size = self.event.total_size();
        if buf.len() < total_size {
            return None;
        }

        let event_bytes = unsafe {
            core::slice::from_raw_parts(
                &self.event as *const InotifyEvent as *const u8,
                core::mem::size_of::<InotifyEvent>(),
            )
        };
        buf[..core::mem::size_of::<InotifyEvent>()].copy_from_slice(event_bytes);

        if let Some(ref name) = self.name {
            let name_bytes = name.as_bytes();
            let offset = core::mem::size_of::<InotifyEvent>();
            buf[offset..offset + name_bytes.len()].copy_from_slice(name_bytes);
            buf[offset + name_bytes.len()] = 0;
            for i in (name_bytes.len() + 1)..(self.event.len as usize) {
                buf[offset + i] = 0;
            }
        }

        Some(total_size)
    }
}

pub struct Watch {
    pub wd: i32,
    pub path: String,
    pub mask: u32,
    pub oneshot: bool,
}

pub struct InotifyInstance {
    pub id: u32,
    pub flags: i32,
    pub watches: BTreeMap<i32, Watch>,
    pub path_to_wd: BTreeMap<String, i32>,
    pub next_wd: AtomicI32,
    pub events: Vec<QueuedEvent>,
    pub cookie_counter: u32,
}

impl InotifyInstance {
    pub fn new(id: u32, flags: i32) -> Self {
        Self {
            id,
            flags,
            watches: BTreeMap::new(),
            path_to_wd: BTreeMap::new(),
            next_wd: AtomicI32::new(1),
            events: Vec::new(),
            cookie_counter: 0,
        }
    }

    pub fn is_nonblock(&self) -> bool {
        (self.flags & IN_NONBLOCK) != 0
    }

    pub fn add_watch(&mut self, path: &str, mask: u32) -> Result<i32, i32> {
        if let Some(&existing_wd) = self.path_to_wd.get(path) {
            if (mask & IN_MASK_CREATE) != 0 {
                return Err(EEXIST);
            }

            if let Some(watch) = self.watches.get_mut(&existing_wd) {
                if (mask & IN_MASK_ADD) != 0 {
                    watch.mask |= mask & IN_ALL_EVENTS;
                } else {
                    watch.mask = mask & IN_ALL_EVENTS;
                }
                watch.oneshot = (mask & IN_ONESHOT) != 0;
            }
            return Ok(existing_wd);
        }

        if self.watches.len() >= MAX_WATCHES_PER_INSTANCE {
            return Err(ENOMEM);
        }

        if !path_exists(path) {
            return Err(ENOENT);
        }

        if (mask & IN_ONLYDIR) != 0 && !is_directory(path) {
            return Err(ENOTDIR);
        }

        let wd = self.next_wd.fetch_add(1, Ordering::SeqCst);
        let watch = Watch {
            wd,
            path: String::from(path),
            mask: mask & IN_ALL_EVENTS,
            oneshot: (mask & IN_ONESHOT) != 0,
        };

        self.path_to_wd.insert(String::from(path), wd);
        self.watches.insert(wd, watch);

        Ok(wd)
    }

    pub fn rm_watch(&mut self, wd: i32) -> Result<(), i32> {
        if let Some(watch) = self.watches.remove(&wd) {
            self.path_to_wd.remove(&watch.path);
            self.queue_event(wd, IN_IGNORED, None);
            Ok(())
        } else {
            Err(EINVAL)
        }
    }

    pub fn queue_event(&mut self, wd: i32, mask: u32, name: Option<&str>) {
        if self.events.len() >= MAX_QUEUED_EVENTS {
            if self.events.last().map(|e| e.event.mask != IN_Q_OVERFLOW).unwrap_or(true) {
                self.events.push(QueuedEvent::new(-1, IN_Q_OVERFLOW, 0, None));
            }
            return;
        }

        self.events.push(QueuedEvent::new(wd, mask, 0, name));
    }

    pub fn queue_move_event(&mut self, from_wd: i32, to_wd: i32, from_name: Option<&str>, to_name: Option<&str>) {
        self.cookie_counter = self.cookie_counter.wrapping_add(1);
        let cookie = self.cookie_counter;

        if from_wd != 0 {
            let event = QueuedEvent::new(from_wd, IN_MOVED_FROM, cookie, from_name);
            self.events.push(event);
        }

        if to_wd != 0 {
            let event = QueuedEvent::new(to_wd, IN_MOVED_TO, cookie, to_name);
            self.events.push(event);
        }
    }

    pub fn read_events(&mut self, buf: &mut [u8]) -> Result<usize, i32> {
        if self.events.is_empty() {
            if self.is_nonblock() {
                return Err(EAGAIN);
            }
            return Err(EAGAIN);
        }

        let mut written = 0;

        while !self.events.is_empty() {
            let event = &self.events[0];
            let event_size = event.event.total_size();

            if written + event_size > buf.len() {
                if written == 0 {
                    return Err(EINVAL);
                }
                break;
            }

            if let Some(size) = event.write_to(&mut buf[written..]) {
                written += size;

                let event = self.events.remove(0);

                let wd = event.event.wd;
                if let Some(watch) = self.watches.get(&wd) {
                    if watch.oneshot && (event.event.mask & IN_ALL_EVENTS) != 0 {
                        let _ = self.rm_watch(wd);
                    }
                }
            }
        }

        Ok(written)
    }

    pub fn has_events(&self) -> bool {
        !self.events.is_empty()
    }
}

pub static INOTIFY_INSTANCES: Mutex<BTreeMap<u32, InotifyInstance>> = Mutex::new(BTreeMap::new());
pub static NEXT_INOTIFY_ID: AtomicU32 = AtomicU32::new(1);

pub static FD_TO_INOTIFY: Mutex<BTreeMap<i32, u32>> = Mutex::new(BTreeMap::new());
pub static NEXT_FD: AtomicU32 = AtomicU32::new(7000);
