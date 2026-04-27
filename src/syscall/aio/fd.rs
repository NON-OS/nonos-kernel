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
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

static AIO_FD_MAP: Mutex<BTreeMap<i32, u64>> = Mutex::new(BTreeMap::new());
static NEXT_AIO_FD: AtomicU64 = AtomicU64::new(1000);

pub fn allocate_aio_fd(ctx_id: u64) -> i32 {
    let fd = NEXT_AIO_FD.fetch_add(1, Ordering::SeqCst) as i32;
    AIO_FD_MAP.lock().insert(fd, ctx_id);
    fd
}

pub fn lookup_context_by_fd(fd: i32) -> Option<u64> {
    AIO_FD_MAP.lock().get(&fd).copied()
}

pub fn release_aio_fd(fd: i32) -> Option<u64> {
    AIO_FD_MAP.lock().remove(&fd)
}

pub fn is_aio_fd(fd: i32) -> bool {
    AIO_FD_MAP.lock().contains_key(&fd)
}

pub fn get_all_aio_fds() -> alloc::vec::Vec<(i32, u64)> {
    AIO_FD_MAP.lock().iter().map(|(&k, &v)| (k, v)).collect()
}

pub fn count_aio_fds() -> usize {
    AIO_FD_MAP.lock().len()
}

pub fn cleanup_fds_for_context(ctx_id: u64) {
    let mut map = AIO_FD_MAP.lock();
    map.retain(|_, &mut v| v != ctx_id);
}

pub fn get_fds_for_context(ctx_id: u64) -> alloc::vec::Vec<i32> {
    AIO_FD_MAP.lock().iter().filter(|(_, &v)| v == ctx_id).map(|(&k, _)| k).collect()
}
