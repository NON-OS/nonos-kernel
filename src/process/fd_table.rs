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
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

pub use super::fd_types::*;

static FD_TABLE: Mutex<BTreeMap<i32, FdEntry>> = Mutex::new(BTreeMap::new());
static NEXT_FD: AtomicU32 = AtomicU32::new(100);

pub fn allocate_fd(mut entry: FdEntry) -> Option<i32> {
    let fd = NEXT_FD.fetch_add(1, Ordering::SeqCst) as i32;
    entry.fd = fd;
    FD_TABLE.lock().insert(fd, entry);
    Some(fd)
}

pub fn allocate_fd_min(mut entry: FdEntry, min_fd: i32) -> Option<i32> {
    let table = FD_TABLE.lock();

    let mut fd = min_fd;
    while table.contains_key(&fd) {
        fd += 1;
        if fd > 65535 {
            return None;
        }
    }
    drop(table);

    entry.fd = fd;
    FD_TABLE.lock().insert(fd, entry);

    let current = NEXT_FD.load(Ordering::SeqCst);
    if (fd + 1) as u32 > current {
        NEXT_FD.store((fd + 1) as u32, Ordering::SeqCst);
    }

    Some(fd)
}

pub fn get_fd(fd: u32) -> Option<FdEntry> {
    let fd = fd as i32;

    if let Some(entry) = FD_TABLE.lock().get(&fd) {
        return Some(entry.clone());
    }

    if crate::syscall::extended::eventfd::is_eventfd(fd) {
        if let Some(efd_id) = crate::syscall::extended::eventfd::fd_to_eventfd_id(fd) {
            let mut entry = FdEntry::new(FdType::EventFd, efd_id as usize);
            entry.fd = fd;
            return Some(entry);
        }
    }

    if crate::syscall::extended::signalfd::is_signalfd(fd) {
        if let Some(sfd_id) = crate::syscall::extended::signalfd::fd_to_signalfd_id(fd) {
            let mut entry = FdEntry::new(FdType::SignalFd, sfd_id as usize);
            entry.fd = fd;
            return Some(entry);
        }
    }

    if crate::ipc::pipe::is_pipe(fd) {
        if let Some((pipe_id, is_read)) = crate::ipc::pipe::fd_to_pipe_id(fd) {
            let mut entry = FdEntry::with_pipe(pipe_id as usize, is_read);
            entry.fd = fd;
            return Some(entry);
        }
    }

    if crate::syscall::extended::timer::is_timerfd(fd) {
        if let Some(tfd_id) = crate::syscall::extended::timer::fd_to_timerfd_id(fd) {
            let mut entry = FdEntry::new(FdType::TimerFd, tfd_id as usize);
            entry.fd = fd;
            return Some(entry);
        }
    }

    if crate::syscall::extended::epoll::is_epoll_fd(fd) {
        if let Some(epoll_id) = crate::syscall::extended::epoll::fd_to_epoll_id(fd) {
            let mut entry = FdEntry::new(FdType::Epoll, epoll_id as usize);
            entry.fd = fd;
            return Some(entry);
        }
    }

    if crate::fs::nonos_vfs::vfs_fd_exists(fd as u32) {
        let mut entry = FdEntry::new(FdType::File, fd as usize);
        entry.fd = fd;
        return Some(entry);
    }

    None
}

pub fn register_fd(fd: i32, mut entry: FdEntry) {
    entry.fd = fd;
    FD_TABLE.lock().insert(fd, entry);
}

pub fn unregister_fd(fd: i32) {
    FD_TABLE.lock().remove(&fd);
}

pub fn set_cloexec(fd: i32, cloexec: bool) -> Result<(), ()> {
    if let Some(entry) = FD_TABLE.lock().get_mut(&fd) {
        if cloexec {
            entry.flags |= FD_CLOEXEC;
        } else {
            entry.flags &= !FD_CLOEXEC;
        }
        return Ok(());
    }
    Err(())
}

pub fn get_cloexec(fd: i32) -> Result<bool, ()> {
    if let Some(entry) = FD_TABLE.lock().get(&fd) {
        return Ok(entry.is_cloexec());
    }
    Err(())
}

pub fn set_status_flags(fd: i32, flags: u32) -> Result<(), ()> {
    if let Some(entry) = FD_TABLE.lock().get_mut(&fd) {
        entry.status_flags = flags;
        return Ok(());
    }
    Err(())
}

pub fn get_status_flags(fd: i32) -> Result<u32, ()> {
    if let Some(entry) = FD_TABLE.lock().get(&fd) {
        return Ok(entry.status_flags);
    }
    Err(())
}

pub fn is_valid(fd: i32) -> bool {
    get_fd(fd as u32).is_some()
}

pub fn get_fd_type(fd: i32) -> Option<FdType> {
    get_fd(fd as u32).map(|e| e.fd_type)
}

pub fn dup_fd(old_fd: i32) -> Option<i32> {
    let entry = get_fd(old_fd as u32)?;
    allocate_fd(FdEntry {
        fd: -1,
        fd_type: entry.fd_type,
        internal_id: entry.internal_id,
        is_read_end: entry.is_read_end,
        is_write_end: entry.is_write_end,
        flags: 0,
        status_flags: entry.status_flags,
    })
}

pub fn dup2_fd(old_fd: i32, new_fd: i32) -> Option<i32> {
    if old_fd == new_fd {
        return Some(new_fd);
    }

    let entry = get_fd(old_fd as u32)?;

    unregister_fd(new_fd);

    register_fd(new_fd, FdEntry {
        fd: new_fd,
        fd_type: entry.fd_type,
        internal_id: entry.internal_id,
        is_read_end: entry.is_read_end,
        is_write_end: entry.is_write_end,
        flags: 0,
        status_flags: entry.status_flags,
    });

    Some(new_fd)
}

pub fn close_cloexec_fds() {
    let to_close: alloc::vec::Vec<i32> = FD_TABLE
        .lock()
        .iter()
        .filter(|(_, entry)| entry.is_cloexec())
        .map(|(&fd, _)| fd)
        .collect();

    for fd in to_close {
        unregister_fd(fd);
    }
}

pub fn close_all_fds() {
    FD_TABLE.lock().clear();
}

pub fn get_stats() -> FdTableStats {
    let table = FD_TABLE.lock();
    let mut file_count = 0;
    let mut socket_count = 0;
    let mut pipe_count = 0;
    let mut eventfd_count = 0;
    let mut timerfd_count = 0;
    let mut signalfd_count = 0;
    let mut epoll_count = 0;

    for entry in table.values() {
        match entry.fd_type {
            FdType::File => file_count += 1,
            FdType::Socket => socket_count += 1,
            FdType::Pipe => pipe_count += 1,
            FdType::EventFd => eventfd_count += 1,
            FdType::TimerFd => timerfd_count += 1,
            FdType::SignalFd => signalfd_count += 1,
            FdType::Epoll => epoll_count += 1,
            _ => {}
        }
    }

    FdTableStats {
        total_fds: table.len(),
        file_count,
        socket_count,
        pipe_count,
        eventfd_count,
        timerfd_count,
        signalfd_count,
        epoll_count,
    }
}
