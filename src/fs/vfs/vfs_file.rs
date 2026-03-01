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

use super::error::{VfsError, VfsResult};
use super::types::{FileMetadata, FileType};
use super::vfs_core::VirtualFileSystem;

impl VirtualFileSystem {
    pub fn rename(&self, old_path: &str, new_path: &str) -> VfsResult<()> {
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

    pub fn write_file(&self, path: &str, data: &[u8]) -> VfsResult<()> {
        self.ensure_parent_dirs(path)?;

        if crate::fs::ramfs::NONOS_FILESYSTEM.exists(path) {
            crate::fs::ramfs::NONOS_FILESYSTEM.write_file(path, data)?;
        } else {
            crate::fs::ramfs::NONOS_FILESYSTEM.create_file(path, data)?;
        }
        Ok(())
    }

    pub fn stat(&self, path: &str) -> VfsResult<FileMetadata> {
        if !self.exists(path) {
            return Err(VfsError::NotFound);
        }

        let is_dir = path.ends_with('/') || path.ends_with("/.dir");

        let size = if is_dir {
            0
        } else {
            self.read_file(path).map(|d| d.len() as u64).unwrap_or(0)
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
