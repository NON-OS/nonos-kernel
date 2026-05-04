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

pub use super::fd_types::*;
pub use super::process_fd_table::ProcessFdTable;
use crate::process::core::table::{CURRENT_PID, PROCESS_TABLE};
use core::sync::atomic::Ordering;

fn with_current<F, T>(f: F) -> Option<T>
where
    F: FnOnce(&ProcessFdTable) -> T,
{
    let pid = CURRENT_PID.load(Ordering::Acquire);
    if pid == 0 {
        return None;
    }
    PROCESS_TABLE.find_by_pid(pid).map(|pcb| f(&pcb.fd_table))
}

pub fn allocate_fd(entry: FdEntry) -> Option<i32> {
    with_current(|t| t.allocate(entry))?
}
pub fn allocate_fd_min(entry: FdEntry, min_fd: i32) -> Option<i32> {
    with_current(|t| t.allocate_min(entry, min_fd))?
}
pub fn register_fd(fd: i32, entry: FdEntry) {
    with_current(|t| {
        t.allocate_at(fd, entry);
    });
}
pub fn unregister_fd(fd: i32) {
    with_current(|t| {
        t.remove(fd);
    });
}
pub fn is_valid(fd: i32) -> bool {
    get_fd(fd as u32).is_some()
}
pub fn get_fd_type(fd: i32) -> Option<FdType> {
    get_fd(fd as u32).map(|e| e.fd_type)
}
pub fn dup_fd(old_fd: i32) -> Option<i32> {
    with_current(|t| t.dup(old_fd))?
}
pub fn dup2_fd(old_fd: i32, new_fd: i32) -> Option<i32> {
    with_current(|t| t.dup2(old_fd, new_fd))?
}
pub fn close_cloexec_fds() {
    with_current(|t| t.close_cloexec());
}
pub fn close_all_fds() {
    with_current(|t| t.close_all());
}

pub fn set_cloexec(fd: i32, cloexec: bool) -> Result<(), ()> {
    match with_current(|t| t.set_cloexec(fd, cloexec)) {
        Some(true) => Ok(()),
        _ => Err(()),
    }
}

pub fn get_cloexec(fd: i32) -> Result<bool, ()> {
    with_current(|t| t.get_cloexec(fd)).flatten().ok_or(())
}

pub fn set_status_flags(fd: i32, flags: u32) -> Result<(), ()> {
    match with_current(|t| t.set_status_flags(fd, flags)) {
        Some(true) => Ok(()),
        _ => Err(()),
    }
}

pub fn get_status_flags(fd: i32) -> Result<u32, ()> {
    with_current(|t| t.get_status_flags(fd)).flatten().ok_or(())
}

pub fn get_stats() -> FdTableStats {
    with_current(|t| t.stats()).unwrap_or(FdTableStats {
        total_fds: 0,
        file_count: 0,
        socket_count: 0,
        pipe_count: 0,
        eventfd_count: 0,
        timerfd_count: 0,
        signalfd_count: 0,
        epoll_count: 0,
    })
}

pub fn get_fd(fd: u32) -> Option<FdEntry> {
    let fd = fd as i32;
    if let Some(entry) = with_current(|t| t.get(fd))? {
        return Some(entry);
    }
    if crate::syscall::extended::signalfd::is_signalfd(fd) {
        if let Some(id) = crate::syscall::extended::signalfd::fd_to_signalfd_id(fd) {
            let mut e = FdEntry::new(FdType::SignalFd, id as usize);
            e.fd = fd;
            return Some(e);
        }
    }
    if crate::ipc::pipe::is_pipe(fd) {
        if let Some((id, is_read)) = crate::ipc::pipe::fd_to_pipe_id(fd) {
            let mut e = FdEntry::with_pipe(id as usize, is_read);
            e.fd = fd;
            return Some(e);
        }
    }
    if crate::syscall::extended::timer::is_timerfd(fd) {
        if let Some(id) = crate::syscall::extended::timer::fd_to_timerfd_id(fd) {
            let mut e = FdEntry::new(FdType::TimerFd, id as usize);
            e.fd = fd;
            return Some(e);
        }
    }
    if crate::syscall::extended::epoll::is_epoll_fd(fd) {
        if let Some(id) = crate::syscall::extended::epoll::fd_to_epoll_id(fd) {
            let mut e = FdEntry::new(FdType::Epoll, id as usize);
            e.fd = fd;
            return Some(e);
        }
    }
    if crate::fs::nonos_vfs::vfs_fd_exists(fd as u32) {
        let mut e = FdEntry::new(FdType::File, fd as usize);
        e.fd = fd;
        return Some(e);
    }
    None
}

pub fn allocate_fd_for_pid(pid: u32, entry: FdEntry) -> Option<i32> {
    PROCESS_TABLE.find_by_pid(pid).and_then(|pcb| pcb.fd_table.allocate(entry))
}

pub fn get_fd_for_pid(pid: u32, fd: i32) -> Option<FdEntry> {
    PROCESS_TABLE.find_by_pid(pid).and_then(|pcb| pcb.fd_table.get(fd))
}

pub fn register_fd_for_pid(pid: u32, fd: i32, entry: FdEntry) {
    if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
        pcb.fd_table.allocate_at(fd, entry);
    }
}

pub fn unregister_fd_for_pid(pid: u32, fd: i32) {
    if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
        pcb.fd_table.remove(fd);
    }
}

pub fn fork_fd_table(parent_pid: u32, child_pid: u32) {
    if let Some(parent) = PROCESS_TABLE.find_by_pid(parent_pid) {
        if let Some(child) = PROCESS_TABLE.find_by_pid(child_pid) {
            let forked = parent.fd_table.fork();
            for fd in 0..MAX_PROCESS_FDS {
                if let Some(entry) = forked.get(fd) {
                    child.fd_table.allocate_at(fd, entry);
                }
            }
        }
    }
}
