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

static SYSFS_MOUNTED: AtomicBool = AtomicBool::new(false);

pub fn sysfs_mount(mountpoint: &str) -> Result<(), i32> {
    if SYSFS_MOUNTED.load(Ordering::SeqCst) {
        return Err(-16);
    }
    crate::fs::vfs::register_mount(mountpoint, "sysfs").map_err(|e| i32::from(e))?;
    SYSFS_MOUNTED.store(true, Ordering::SeqCst);
    init_sysfs_tree();
    Ok(())
}

pub fn sysfs_unmount() -> Result<(), i32> {
    if !SYSFS_MOUNTED.load(Ordering::SeqCst) {
        return Err(-22);
    }
    SYSFS_MOUNTED.store(false, Ordering::SeqCst);
    Ok(())
}

pub fn is_sysfs_mounted() -> bool {
    SYSFS_MOUNTED.load(Ordering::SeqCst)
}

fn init_sysfs_tree() {
    super::class::init_class_subsystem();
    super::devices::init_devices_subsystem();
    super::bus::init_bus_subsystem();
    super::kernel::init_kernel_subsystem();
    super::module::init_module_subsystem();
}

pub fn sysfs_statfs() -> SysfsStatFs {
    SysfsStatFs {
        f_type: 0x62656572,
        f_bsize: 4096,
        f_blocks: 0,
        f_bfree: 0,
        f_bavail: 0,
        f_files: 0,
        f_ffree: 0,
        f_namelen: 255,
    }
}

#[repr(C)]
pub struct SysfsStatFs {
    pub f_type: u64,
    pub f_bsize: u64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_namelen: u64,
}
