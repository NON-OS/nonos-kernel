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
use spin::Mutex;

use super::error::{VfsError, VfsResult};
use super::types::{FileMetadata, FileType};
use super::vfs_core::VirtualFileSystem;

/// # Safety
/// Global VFS operation lock prevents TOCTOU races in multi-step operations.
/// All compound operations must hold this lock for their entire duration.
static VFS_OP_LOCK: Mutex<()> = Mutex::new(());

impl VirtualFileSystem {
    /// # Safety
    /// Atomic copy operation. Holds VFS lock to prevent TOCTOU between
    /// read and create operations.
    pub fn copy(&self, src: &str, dst: &str) -> VfsResult<()> {
        let _lock = VFS_OP_LOCK.lock();
        let data: Vec<u8> = crate::fs::ramfs::NONOS_FILESYSTEM.read_file(src)?;
        crate::fs::ramfs::NONOS_FILESYSTEM.create_file(dst, &data)?;
        self.inner.lock().vfs_stats.copy_ops += 1;
        Ok(())
    }

    /// # Safety
    /// Atomic rename operation. Holds VFS lock to prevent TOCTOU between
    /// read, create, and delete operations.
    pub fn rename(&self, old_path: &str, new_path: &str) -> VfsResult<()> {
        let _lock = VFS_OP_LOCK.lock();
        let data = crate::fs::ramfs::NONOS_FILESYSTEM.read_file(old_path)?;
        crate::fs::ramfs::NONOS_FILESYSTEM.create_file(new_path, &data)?;
        crate::fs::ramfs::NONOS_FILESYSTEM.delete_file(old_path)?;
        self.inner.lock().vfs_stats.rename_ops += 1;
        Ok(())
    }

    pub fn unlink(&self, path: &str) -> VfsResult<()> {
        crate::fs::ramfs::NONOS_FILESYSTEM.delete_file(path)?;
        self.inner.lock().vfs_stats.unlink_ops += 1;
        Ok(())
    }

    /// # Safety
    /// Atomic write operation. Uses write_or_create to avoid exists() check
    /// that could race with concurrent operations.
    pub fn write_file(&self, path: &str, data: &[u8]) -> VfsResult<()> {
        let _lock = VFS_OP_LOCK.lock();
        self.ensure_parent_dirs(path)?;
        crate::fs::ramfs::NONOS_FILESYSTEM.write_or_create(path, data)?;
        Ok(())
    }

    /// # Safety
    /// Atomic stat operation. Reads file data atomically to avoid TOCTOU
    /// between exists check and size read.
    pub fn stat(&self, path: &str) -> VfsResult<FileMetadata> {
        let _lock = VFS_OP_LOCK.lock();

        let is_dir = path.ends_with('/') || path.ends_with("/.dir");

        let size = if is_dir {
            0
        } else {
            match crate::fs::ramfs::NONOS_FILESYSTEM.read_file(path) {
                Ok(data) => data.len() as u64,
                Err(_) => return Err(VfsError::NotFound),
            }
        };

        let mut inode = 1u64;
        for byte in path.bytes() {
            inode = inode.wrapping_mul(31).wrapping_add(byte as u64);
        }

        let mode = if is_dir { 0o040755 } else { 0o100644 };
        let now = crate::time::timestamp_secs();

        Ok(FileMetadata {
            size,
            atime: now,
            mtime: now,
            ctime: now,
            file_type: if is_dir { FileType::Directory } else { FileType::File },
            mode,
            inode,
        })
    }
}
