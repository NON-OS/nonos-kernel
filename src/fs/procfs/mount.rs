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

use super::types::ProcInode;
use core::sync::atomic::{AtomicBool, Ordering};

static PROCFS_MOUNTED: AtomicBool = AtomicBool::new(false);
static mut PROCFS_ROOT: Option<ProcInode> = None;

pub fn procfs_mount(mountpoint: &str) -> Result<(), i32> {
    if PROCFS_MOUNTED.load(Ordering::SeqCst) {
        return Err(-16);
    }
    unsafe {
        PROCFS_ROOT = Some(ProcInode::root());
    }
    PROCFS_MOUNTED.store(true, Ordering::SeqCst);
    crate::fs::vfs::register_mount(mountpoint, "proc").map_err(|e| i32::from(e))?;
    Ok(())
}

pub fn procfs_unmount() -> Result<(), i32> {
    if !PROCFS_MOUNTED.load(Ordering::SeqCst) {
        return Err(-22);
    }
    PROCFS_MOUNTED.store(false, Ordering::SeqCst);
    unsafe {
        PROCFS_ROOT = None;
    }
    Ok(())
}

pub fn is_procfs_mounted() -> bool {
    PROCFS_MOUNTED.load(Ordering::SeqCst)
}

pub fn get_root_inode() -> u64 {
    1
}

pub fn procfs_statfs() -> ProcStatFs {
    ProcStatFs {
        f_type: 0x9fa0,
        f_bsize: 4096,
        f_blocks: 0,
        f_bfree: 0,
        f_bavail: 0,
        f_files: 0,
        f_ffree: 0,
        f_namelen: 255,
        f_frsize: 4096,
    }
}

#[repr(C)]
pub struct ProcStatFs {
    pub f_type: u64,
    pub f_bsize: u64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_namelen: u64,
    pub f_frsize: u64,
}
