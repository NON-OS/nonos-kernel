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
use core::sync::atomic::{Ordering, compiler_fence};
use spin::Once;

use super::error::{VfsError, VfsResult};
use super::types::{
    FileMetadata, FileSystemType, FileType, IoStatistics,
    MountPoint, VfsStatistics, MAX_MOUNTS,
};
use super::fd_table::clear_fd_table;

#[inline]
fn secure_zeroize(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[inline]
fn secure_zeroize_string(s: &mut String) {
    let bytes = unsafe { s.as_bytes_mut() };
    secure_zeroize(bytes);
    s.clear();
}

#[derive(Debug)]
struct VirtualFileSystemInner {
    mounts: Vec<MountPoint>,
    pending_ops: usize,
    io_stats: IoStatistics,
    vfs_stats: VfsStatistics,
}

#[derive(Debug)]
pub struct VirtualFileSystem {
    inner: spin::Mutex<VirtualFileSystemInner>,
}

impl VirtualFileSystem {
    pub fn new() -> Self {
        Self {
            inner: spin::Mutex::new(VirtualFileSystemInner {
                mounts: Vec::new(),
                pending_ops: 0,
                io_stats: IoStatistics::default(),
                vfs_stats: VfsStatistics::default(),
            }),
        }
    }

    pub fn sync_metadata(&self) {
    }

    pub fn process_pending_operations(&self, max_ops: usize) -> usize {
        let mut g = self.inner.lock();
        let to_process = core::cmp::min(g.pending_ops, max_ops);
        g.pending_ops = g.pending_ops.saturating_sub(to_process);
        to_process
    }

    pub fn mount(&self, mount_path: &str, fs_type: FileSystemType) {
        let mut g = self.inner.lock();
        if g.mounts.len() < MAX_MOUNTS {
            g.mounts.push(MountPoint {
                mount_path: String::from(mount_path),
                filesystem: fs_type,
            });
            g.vfs_stats.mounts += 1;
        }
    }

    pub fn mounts(&self) -> Vec<MountPoint> {
        self.inner.lock().mounts.clone()
    }

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

    pub fn rename(&self, old_path: &str, new_path: &str) -> VfsResult<()> {
        let data = crate::fs::ramfs::NONOS_FILESYSTEM.read_file(old_path)?;

        crate::fs::ramfs::NONOS_FILESYSTEM.create_file(new_path, &data)?;

        crate::fs::ramfs::NONOS_FILESYSTEM.delete_file(old_path)?;

        self.inner.lock().vfs_stats.rename_ops += 1;
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
            .filter(|f| f.starts_with(&prefix) && !f.ends_with("/.dir"))
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

    pub fn unlink(&self, path: &str) -> VfsResult<()> {
        crate::fs::ramfs::NONOS_FILESYSTEM.delete_file(path)?;
        self.inner.lock().vfs_stats.unlink_ops += 1;
        Ok(())
    }

    pub fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
        crate::fs::ramfs::NONOS_FILESYSTEM.read_file(path)
            .map_err(VfsError::from)
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

    pub fn exists(&self, path: &str) -> bool {
        crate::fs::ramfs::NONOS_FILESYSTEM.exists(path)
    }

    pub fn list_dir(&self, path: &str) -> VfsResult<Vec<String>> {
        crate::fs::ramfs::list_dir(path).map_err(VfsError::from)
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

    pub fn stats(&self) -> VfsStatistics {
        self.inner.lock().vfs_stats.clone()
    }

    pub fn clear_all(&self) {
        let mut inner = self.inner.lock();

        for mount in inner.mounts.iter_mut() {
            secure_zeroize_string(&mut mount.mount_path);
        }
        inner.mounts.clear();
        inner.pending_ops = 0;
        inner.io_stats = IoStatistics::default();
        inner.vfs_stats = VfsStatistics::default();

        compiler_fence(Ordering::SeqCst);
    }
}

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
