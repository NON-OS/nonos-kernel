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

use alloc::format;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::fs::ramfs;
use crate::fs::fd::error::{FdError, FdResult};
use crate::fs::fd::types::{O_RDWR, O_CLOEXEC};
use crate::fs::fd::table::fd_open;

static MEMFD_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn create_memfd(name: &str, flags: u32) -> FdResult<i32> {
    let id = MEMFD_COUNTER.fetch_add(1, Ordering::Relaxed);
    let memfd_path = format!("/dev/memfd/{}_{}", id, name);

    ramfs::NONOS_FILESYSTEM
        .create_file(&memfd_path, &[])
        .map_err(FdError::from)?;

    let open_flags = if (flags & 1) != 0 {
        O_RDWR | O_CLOEXEC
    } else {
        O_RDWR
    };

    fd_open(&memfd_path, open_flags)
}
