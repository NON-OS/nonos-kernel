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

use super::clock::get_clock_time;
use super::constants::TFD_CLOEXEC;
use super::timerfd_types::{FD_TO_TIMERFD, TIMERFD_INSTANCES};
use super::types::TimerFdPollInfo;

pub fn timerfd_read(tfd_id: u32, blocking: bool) -> Option<u64> {
    loop {
        {
            let mut instances = TIMERFD_INSTANCES.lock();
            if let Some(tfd) = instances.get_mut(&tfd_id) {
                update_expirations(tfd);
                if tfd.expirations > 0 {
                    let count = tfd.expirations;
                    tfd.expirations = 0;
                    return Some(count);
                }
                if !blocking || (tfd.flags & super::constants::TFD_NONBLOCK) != 0 {
                    return None;
                }
            } else {
                return None;
            }
        }
        crate::sched::yield_now();
    }
}

fn update_expirations(tfd: &mut super::timerfd_types::TimerFd) {
    if !tfd.armed || tfd.expire_time == 0 {
        return;
    }
    let now = get_clock_time(tfd.clock_id);
    if now >= tfd.expire_time {
        if tfd.interval > 0 {
            let elapsed = now - tfd.expire_time;
            tfd.expirations += 1 + (elapsed / tfd.interval);
            tfd.expire_time += tfd.interval * (1 + elapsed / tfd.interval);
        } else {
            tfd.expirations = 1;
            tfd.armed = false;
        }
    }
}

pub fn get_timerfd_info_for_poll(tfd_id: u32) -> Option<TimerFdPollInfo> {
    let mut instances = TIMERFD_INSTANCES.lock();
    if let Some(tfd) = instances.get_mut(&tfd_id) {
        update_expirations(tfd);
        Some(TimerFdPollInfo { expirations: tfd.expirations })
    } else {
        None
    }
}

pub fn allocate_timerfd(tfd_id: u32, flags: i32) -> Option<i32> {
    use crate::process::fd_table;
    let close_on_exec = (flags & TFD_CLOEXEC) != 0;
    let mut entry = fd_table::FdEntry::new(fd_table::FdType::TimerFd, tfd_id as usize);
    entry.flags = if close_on_exec { fd_table::FD_CLOEXEC } else { 0 };
    entry.is_read_end = true;
    let fd = fd_table::allocate_fd(entry)?;
    FD_TO_TIMERFD.lock().insert(fd, tfd_id);
    Some(fd)
}

pub fn get_timerfd_id(fd: i32) -> Option<u32> {
    if let Some(&id) = FD_TO_TIMERFD.lock().get(&fd) {
        return Some(id);
    }
    use crate::process::fd_table;
    let entry = fd_table::get_fd(fd as u32)?;
    if entry.fd_type != fd_table::FdType::TimerFd {
        return None;
    }
    Some(entry.internal_id as u32)
}

pub fn is_timerfd(fd: i32) -> bool {
    FD_TO_TIMERFD.lock().contains_key(&fd)
}
pub fn fd_to_timerfd_id(fd: i32) -> Option<u32> {
    FD_TO_TIMERFD.lock().get(&fd).copied()
}
pub fn close_timerfd(tfd_id: u32) {
    TIMERFD_INSTANCES.lock().remove(&tfd_id);
}
