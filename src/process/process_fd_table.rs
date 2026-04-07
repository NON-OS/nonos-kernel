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

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};
use spin::RwLock;
use super::fd_types::{FdEntry, FdType, FdTableStats, FD_CLOEXEC, MAX_PROCESS_FDS, STDIO_FDS};

pub struct ProcessFdTable {
    entries: RwLock<BTreeMap<i32, FdEntry>>,
    next_fd: AtomicI32,
}

impl core::fmt::Debug for ProcessFdTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProcessFdTable").field("count", &self.entries.read().len()).finish()
    }
}

impl ProcessFdTable {
    pub fn new() -> Self {
        Self { entries: RwLock::new(BTreeMap::new()), next_fd: AtomicI32::new(STDIO_FDS) }
    }

    pub fn fork(&self) -> Self {
        let entries = self.entries.read();
        let mut new_entries = BTreeMap::new();
        for (&fd, entry) in entries.iter() {
            if !entry.is_cloexec() { new_entries.insert(fd, entry.clone()); }
        }
        Self { entries: RwLock::new(new_entries), next_fd: AtomicI32::new(self.next_fd.load(Ordering::Acquire)) }
    }

    pub fn allocate(&self, mut entry: FdEntry) -> Option<i32> {
        let mut table = self.entries.write();
        let mut fd = self.next_fd.load(Ordering::Acquire);
        while table.contains_key(&fd) {
            fd = fd.checked_add(1)?;
            if fd >= MAX_PROCESS_FDS { return None; }
        }
        entry.fd = fd;
        table.insert(fd, entry);
        self.next_fd.store(fd.saturating_add(1).min(MAX_PROCESS_FDS), Ordering::Release);
        Some(fd)
    }

    pub fn allocate_at(&self, fd: i32, mut entry: FdEntry) -> Option<i32> {
        if fd < 0 || fd >= MAX_PROCESS_FDS { return None; }
        entry.fd = fd;
        self.entries.write().insert(fd, entry);
        let current = self.next_fd.load(Ordering::Acquire);
        if fd >= current { self.next_fd.store(fd.saturating_add(1).min(MAX_PROCESS_FDS), Ordering::Release); }
        Some(fd)
    }

    pub fn allocate_min(&self, mut entry: FdEntry, min_fd: i32) -> Option<i32> {
        if min_fd < 0 || min_fd >= MAX_PROCESS_FDS { return None; }
        let mut table = self.entries.write();
        let mut fd = min_fd;
        while table.contains_key(&fd) {
            fd = fd.checked_add(1)?;
            if fd >= MAX_PROCESS_FDS { return None; }
        }
        entry.fd = fd;
        table.insert(fd, entry);
        let current = self.next_fd.load(Ordering::Acquire);
        if fd >= current { self.next_fd.store(fd.saturating_add(1).min(MAX_PROCESS_FDS), Ordering::Release); }
        Some(fd)
    }

    #[inline] pub fn get(&self, fd: i32) -> Option<FdEntry> { self.entries.read().get(&fd).cloned() }
    #[inline] pub fn all_fds(&self) -> Vec<i32> { self.entries.read().keys().copied().collect() }
    #[inline] pub fn remove(&self, fd: i32) -> Option<FdEntry> { self.entries.write().remove(&fd) }
    #[inline] pub fn is_valid(&self, fd: i32) -> bool { self.entries.read().contains_key(&fd) }
    #[inline] pub fn get_type(&self, fd: i32) -> Option<FdType> { self.entries.read().get(&fd).map(|e| e.fd_type) }
    #[inline] pub fn count(&self) -> usize { self.entries.read().len() }
    #[inline] pub fn close_all(&self) { self.entries.write().clear(); }
    #[inline] pub fn get_cloexec(&self, fd: i32) -> Option<bool> { self.entries.read().get(&fd).map(|e| e.is_cloexec()) }
    #[inline] pub fn get_status_flags(&self, fd: i32) -> Option<u32> { self.entries.read().get(&fd).map(|e| e.status_flags) }

    pub fn set_cloexec(&self, fd: i32, cloexec: bool) -> bool {
        if let Some(entry) = self.entries.write().get_mut(&fd) {
            if cloexec { entry.flags |= FD_CLOEXEC; } else { entry.flags &= !FD_CLOEXEC; }
            true
        } else { false }
    }

    pub fn set_status_flags(&self, fd: i32, flags: u32) -> bool {
        if let Some(entry) = self.entries.write().get_mut(&fd) { entry.status_flags = flags; true } else { false }
    }

    pub fn dup(&self, old_fd: i32) -> Option<i32> {
        let entry = self.get(old_fd)?;
        let mut new_entry = entry.clone();
        new_entry.flags = 0;
        self.allocate(new_entry)
    }

    pub fn dup2(&self, old_fd: i32, new_fd: i32) -> Option<i32> {
        if new_fd < 0 || new_fd >= MAX_PROCESS_FDS { return None; }
        let mut table = self.entries.write();
        if old_fd == new_fd { return if table.contains_key(&old_fd) { Some(new_fd) } else { None }; }
        let entry = table.get(&old_fd)?.clone();
        table.remove(&new_fd);
        let mut new_entry = entry;
        new_entry.fd = new_fd;
        new_entry.flags = 0;
        table.insert(new_fd, new_entry);
        Some(new_fd)
    }

    pub fn close_cloexec(&self) {
        let mut table = self.entries.write();
        let to_close: Vec<i32> = table.iter().filter(|(_, e)| e.is_cloexec()).map(|(&fd, _)| fd).collect();
        for fd in to_close { table.remove(&fd); }
    }

    pub fn stats(&self) -> FdTableStats {
        let table = self.entries.read();
        let mut s = FdTableStats { total_fds: table.len(), file_count: 0, socket_count: 0, pipe_count: 0, eventfd_count: 0, timerfd_count: 0, signalfd_count: 0, epoll_count: 0 };
        for e in table.values() {
            match e.fd_type {
                FdType::File | FdType::Directory => s.file_count += 1,
                FdType::Socket => s.socket_count += 1,
                FdType::Pipe => s.pipe_count += 1,
                FdType::EventFd => s.eventfd_count += 1,
                FdType::TimerFd => s.timerfd_count += 1,
                FdType::SignalFd => s.signalfd_count += 1,
                FdType::Epoll => s.epoll_count += 1,
                FdType::Unknown => {}
            }
        }
        s
    }
}
