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

use alloc::vec::Vec;
use core::sync::atomic::{Ordering, compiler_fence};
use spin::Once;

use super::error::{VfsError, VfsResult};
use super::fd_ops::clear_fd_table;
use super::vfs_core::VirtualFileSystem;

static VFS: Once<VirtualFileSystem> = Once::new();

pub fn init_vfs() {
    VFS.call_once(|| VirtualFileSystem::new());
}

pub fn get_vfs() -> Option<&'static VirtualFileSystem> {
    VFS.get()
}

pub fn get_vfs_mut() -> Option<&'static VirtualFileSystem> {
    VFS.get()
}

pub fn clear_vfs_caches() {
    clear_fd_table();

    if let Some(vfs) = VFS.get() {
        vfs.clear_all();
    }

    compiler_fence(Ordering::SeqCst);
}

pub fn vfs_write_file(path: &str, data: &[u8]) -> VfsResult<()> {
    if let Some(vfs) = get_vfs() {
        vfs.write_file(path, data)
    } else {
        Err(VfsError::NotInitialized)
    }
}

pub fn vfs_read_file(path: &str) -> VfsResult<Vec<u8>> {
    if let Some(vfs) = get_vfs() {
        vfs.read_file(path)
    } else {
        Err(VfsError::NotInitialized)
    }
}
