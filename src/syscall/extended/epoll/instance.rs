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
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use super::types::*;
use super::check::check_fd_events;

#[derive(Clone)]
pub struct EpollEntry {
    pub fd: i32,
    pub events: u32,
    pub data: u64,
    pub oneshot_triggered: bool,
}

pub struct EpollInstance {
    pub interest_list: BTreeMap<i32, EpollEntry>,
    pub ready_events: Vec<EpollEvent>,
}

impl EpollInstance {
    pub fn new() -> Self {
        Self {
            interest_list: BTreeMap::new(),
            ready_events: Vec::new(),
        }
    }

    pub fn add(&mut self, fd: i32, events: u32, data: u64) -> Result<(), i32> {
        if self.interest_list.contains_key(&fd) {
            return Err(EEXIST);
        }
        if self.interest_list.len() >= MAX_EVENTS_PER_INSTANCE {
            return Err(ENOMEM);
        }

        self.interest_list.insert(fd, EpollEntry {
            fd,
            events,
            data,
            oneshot_triggered: false,
        });
        Ok(())
    }

    pub fn modify(&mut self, fd: i32, events: u32, data: u64) -> Result<(), i32> {
        match self.interest_list.get_mut(&fd) {
            Some(entry) => {
                entry.events = events;
                entry.data = data;
                entry.oneshot_triggered = false;
                Ok(())
            }
            None => Err(ENOENT),
        }
    }

    pub fn delete(&mut self, fd: i32) -> Result<(), i32> {
        match self.interest_list.remove(&fd) {
            Some(_) => Ok(()),
            None => Err(ENOENT),
        }
    }

    pub fn poll(&mut self, max_events: usize) -> Vec<EpollEvent> {
        let mut ready = Vec::with_capacity(max_events.min(self.interest_list.len()));

        for (fd, entry) in self.interest_list.iter_mut() {
            if entry.oneshot_triggered && (entry.events & EPOLLONESHOT) != 0 {
                continue;
            }

            let current_events = check_fd_events(*fd, entry.events);

            if current_events != 0 {
                ready.push(EpollEvent {
                    events: current_events,
                    data: entry.data,
                });

                if (entry.events & EPOLLONESHOT) != 0 {
                    entry.oneshot_triggered = true;
                }

                if ready.len() >= max_events {
                    break;
                }
            }
        }

        ready
    }
}

pub static EPOLL_INSTANCES: Mutex<BTreeMap<u32, EpollInstance>> = Mutex::new(BTreeMap::new());
pub static NEXT_EPOLL_ID: AtomicU32 = AtomicU32::new(1);
pub static EPOLL_WAKEUP_COUNT: AtomicU32 = AtomicU32::new(0);

pub fn allocate_epoll_id() -> u32 {
    NEXT_EPOLL_ID.fetch_add(1, Ordering::SeqCst)
}

pub fn get_epoll_id() -> u32 {
    NEXT_EPOLL_ID.load(Ordering::Relaxed)
}

pub fn record_wakeup() {
    EPOLL_WAKEUP_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub fn total_wakeups() -> u32 {
    EPOLL_WAKEUP_COUNT.load(Ordering::Acquire)
}
