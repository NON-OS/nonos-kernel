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

use alloc::{format, string::String, string::ToString, vec::Vec};

use super::error::{VfsError, VfsResult};
use super::vfs_core::VirtualFileSystem;

impl VirtualFileSystem {
    pub fn mkdir_all(&self, path: &str) -> VfsResult<()> {
        let normalized = path.trim_end_matches('/');
        if normalized.is_empty() {
            return Ok(());
        }

        let components: Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();
        let mut current_path = String::new();

        for component in components {
            if current_path.is_empty() {
                current_path = format!("/{}", component);
            } else {
                current_path = format!("{}/{}", current_path, component);
            }

            let marker_path = format!("{}/.dir", current_path);

            if !crate::fs::ramfs::NONOS_FILESYSTEM.exists(&marker_path) {
                crate::fs::ramfs::NONOS_FILESYSTEM.create_file(&marker_path, b"")?;
                self.inner.lock().vfs_stats.mkdir_ops += 1;
            }
        }

        Ok(())
    }

    pub fn mkdir(&self, path: &str) -> VfsResult<()> {
        let normalized = path.trim_end_matches('/');
        if normalized.is_empty() {
            return Err(VfsError::InvalidPath);
        }

        if let Some(parent_end) = normalized.rfind('/') {
            if parent_end > 0 {
                let parent = &normalized[..parent_end];
                let parent_marker = format!("{}/.dir", parent);
                if !crate::fs::ramfs::NONOS_FILESYSTEM.exists(&parent_marker) {
                    return Err(VfsError::NotFound);
                }
            }
        }

        let marker_path = format!("{}/.dir", normalized);
        if crate::fs::ramfs::NONOS_FILESYSTEM.exists(&marker_path) {
            return Err(VfsError::AlreadyExists);
        }

        crate::fs::ramfs::NONOS_FILESYSTEM.create_file(&marker_path, b"")?;
        self.inner.lock().vfs_stats.mkdir_ops += 1;
        Ok(())
    }

    pub fn ensure_parent_dirs(&self, file_path: &str) -> VfsResult<()> {
        if let Some(parent_end) = file_path.rfind('/') {
            if parent_end > 0 {
                let parent = &file_path[..parent_end];
                self.mkdir_all(parent)?;
            }
        }
        Ok(())
    }

    pub fn rmdir(&self, path: &str) -> VfsResult<()> {
        let files = crate::fs::ramfs::NONOS_FILESYSTEM.list_files();
        let prefix = if path.ends_with('/') {
            path.to_string()
        } else {
            format!("{}/", path)
        };

        let entries: Vec<_> = files.iter()
            .filter(|f: &&String| f.starts_with(&prefix) && !f.ends_with("/.dir"))
            .collect();

        if !entries.is_empty() {
            return Err(VfsError::DirectoryNotEmpty);
        }

        let marker_path = if path.ends_with('/') {
            format!("{}.dir", path.trim_end_matches('/'))
        } else {
            format!("{}/.dir", path)
        };

        let _ = crate::fs::ramfs::NONOS_FILESYSTEM.delete_file(&marker_path);

        self.inner.lock().vfs_stats.rmdir_ops += 1;
        Ok(())
    }

    pub fn list_dir(&self, path: &str) -> VfsResult<Vec<String>> {
        crate::fs::ramfs::list_dir(path).map_err(VfsError::from)
    }
}
