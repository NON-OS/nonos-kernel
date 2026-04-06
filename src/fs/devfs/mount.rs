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

use core::sync::atomic::{AtomicBool, Ordering};

static DEVFS_MOUNTED: AtomicBool = AtomicBool::new(false);

pub fn devfs_mount(mountpoint: &str) -> Result<(), i32> {
    if DEVFS_MOUNTED.load(Ordering::SeqCst) {
        return Err(-16);
    }
    crate::fs::vfs::register_mount(mountpoint, "devtmpfs", 1)?;
    DEVFS_MOUNTED.store(true, Ordering::SeqCst);
    init_standard_devices();
    Ok(())
}

pub fn devfs_unmount() -> Result<(), i32> {
    if !DEVFS_MOUNTED.load(Ordering::SeqCst) {
        return Err(-22);
    }
    DEVFS_MOUNTED.store(false, Ordering::SeqCst);
    Ok(())
}

pub fn is_devfs_mounted() -> bool {
    DEVFS_MOUNTED.load(Ordering::SeqCst)
}

fn init_standard_devices() {
    super::char::null::register_null();
    super::char::zero::register_zero();
    super::char::full::register_full();
    super::char::random::register_random();
    super::char::tty::register_tty_devices();
    super::char::ptmx::register_ptmx();
    super::pts::init_pts();
}

pub fn devfs_statfs() -> DevfsStatFs {
    DevfsStatFs {
        f_type: 0x1373,
        f_bsize: 4096,
        f_blocks: 0,
        f_bfree: 0,
        f_bavail: 0,
        f_files: super::registry::device_count() as u64,
        f_ffree: 0,
        f_namelen: 255,
    }
}

#[repr(C)]
pub struct DevfsStatFs {
    pub f_type: u64,
    pub f_bsize: u64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_namelen: u64,
}
