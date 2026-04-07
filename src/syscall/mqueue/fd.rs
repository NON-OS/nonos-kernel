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
use spin::Mutex;

static MQ_FD_FLAGS: Mutex<BTreeMap<i32, u32>> = Mutex::new(BTreeMap::new());

pub fn set_fd_flags(fd: i32, flags: u32) {
    MQ_FD_FLAGS.lock().insert(fd, flags);
}

pub fn get_fd_flags(fd: i32) -> Option<u32> {
    MQ_FD_FLAGS.lock().get(&fd).copied()
}

pub fn is_nonblocking(fd: i32) -> bool {
    MQ_FD_FLAGS.lock().get(&fd).map(|f| f & 0o4000 != 0).unwrap_or(false)
}

pub fn is_cloexec(fd: i32) -> bool {
    MQ_FD_FLAGS.lock().get(&fd).map(|f| f & 0o2000000 != 0).unwrap_or(false)
}

pub fn clear_fd_flags(fd: i32) {
    MQ_FD_FLAGS.lock().remove(&fd);
}

pub fn close_mq_fd(fd: i32) -> Result<(), i32> {
    let mut flags = MQ_FD_FLAGS.lock();
    flags.remove(&fd);
    Ok(())
}

pub fn get_all_mq_fds() -> alloc::vec::Vec<i32> {
    MQ_FD_FLAGS.lock().keys().copied().collect()
}

pub fn validate_mq_fd(fd: i32) -> bool {
    fd >= 100 && MQ_FD_FLAGS.lock().contains_key(&fd)
}

pub fn get_fd_count() -> usize {
    MQ_FD_FLAGS.lock().len()
}
