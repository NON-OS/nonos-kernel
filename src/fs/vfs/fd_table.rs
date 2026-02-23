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

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering, compiler_fence};
use spin::RwLock;

use super::error::{VfsError, VfsResult};
use super::types::{IoStatistics, OpenFlags, MAX_FDS, MAX_PATH_LEN, RESERVED_FDS};

#[inline]
fn secure_zeroize(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[inline]
fn secure_zeroize_string(s: &mut String) {
    // Safety: We're zeroing the string's buffer before clearing it
    let bytes = unsafe { s.as_bytes_mut() };
    secure_zeroize(bytes);
    s.clear();
}

#[derive(Debug, Clone)]
pub struct OpenFile {
    pub path: String,
    pub flags: OpenFlags,
    pub position: u64,
    pub size: u64,
}

impl OpenFile {
    fn secure_clear(&mut self) {
        secure_zeroize_string(&mut self.path);
        self.position = 0;
        self.size = 0;
    }
}

impl Drop for OpenFile {
    fn drop(&mut self) {
        self.secure_clear();
    }
}

struct FileDescriptorTable {
    files: BTreeMap<u32, OpenFile>,
    next_fd: AtomicU32,
    stats: IoStatistics,
}

impl FileDescriptorTable {
    const fn new() -> Self {
        FileDescriptorTable {
            files: BTreeMap::new(),
            next_fd: AtomicU32::new(RESERVED_FDS),
            stats: IoStatistics {
                reads: 0,
                writes: 0,
                flushes: 0,
                bytes_read: 0,
                bytes_written: 0,
            },
        }
    }

    fn allocate_fd(&self) -> VfsResult<u32> {
        for fd in RESERVED_FDS..MAX_FDS {
            if !self.files.contains_key(&fd) {
                return Ok(fd);
            }
        }
        Err(VfsError::TooManyOpenFiles)
    }

    fn open(&mut self, path: &str, flags: OpenFlags) -> VfsResult<u32> {
        if path.is_empty() {
            return Err(VfsError::InvalidPath);
        }
        if path.len() > MAX_PATH_LEN {
            return Err(VfsError::PathTooLong);
        }

        let fd = self.allocate_fd()?;

        let file_exists = crate::fs::ramfs::NONOS_FILESYSTEM.exists(path);

        if !file_exists && !flags.contains(OpenFlags::CREATE) {
            return Err(VfsError::NotFound);
        }

        if !file_exists && flags.contains(OpenFlags::CREATE) {
            crate::fs::ramfs::NONOS_FILESYSTEM.create_file(path, b"")?;
        }

        if file_exists && flags.contains(OpenFlags::TRUNCATE) && flags.contains(OpenFlags::WRITE) {
            crate::fs::ramfs::NONOS_FILESYSTEM.write_file(path, b"")?;
        }

        let size = crate::fs::ramfs::NONOS_FILESYSTEM.read_file(path)
            .map(|data| data.len() as u64)
            .unwrap_or(0);

        let position = if flags.contains(OpenFlags::APPEND) {
            size
        } else {
            0
        };

        self.files.insert(fd, OpenFile {
            path: path.into(),
            flags,
            position,
            size,
        });

        Ok(fd)
    }

    fn close(&mut self, fd: u32) -> VfsResult<()> {
        if let Some(mut file) = self.files.remove(&fd) {
            file.secure_clear();
            Ok(())
        } else {
            Err(VfsError::InvalidFd)
        }
    }

    fn read(&mut self, fd: u32, buffer: &mut [u8]) -> VfsResult<usize> {
        let file = self.files.get_mut(&fd).ok_or(VfsError::InvalidFd)?;

        if !file.flags.is_readable() {
            return Err(VfsError::NotReadable);
        }

        let data = crate::fs::ramfs::NONOS_FILESYSTEM.read_file(&file.path)?;
        let pos = file.position as usize;

        if pos >= data.len() {
            return Ok(0);
        }

        let available = data.len() - pos;
        let to_read = core::cmp::min(buffer.len(), available);

        buffer[..to_read].copy_from_slice(&data[pos..pos + to_read]);
        file.position += to_read as u64;

        self.stats.reads += 1;
        self.stats.bytes_read += to_read as u64;

        Ok(to_read)
    }

    fn write(&mut self, fd: u32, buffer: &[u8]) -> VfsResult<usize> {
        let file = self.files.get_mut(&fd).ok_or(VfsError::InvalidFd)?;

        if !file.flags.is_writable() {
            return Err(VfsError::NotWritable);
        }

        let mut data = crate::fs::ramfs::NONOS_FILESYSTEM.read_file(&file.path)
            .unwrap_or_else(|_| Vec::new());

        let pos = file.position as usize;

        if pos > data.len() {
            data.resize(pos, 0);
        }

        if pos + buffer.len() > data.len() {
            data.resize(pos + buffer.len(), 0);
        }

        data[pos..pos + buffer.len()].copy_from_slice(buffer);

        crate::fs::ramfs::NONOS_FILESYSTEM.write_file(&file.path, &data)?;

        file.position += buffer.len() as u64;
        file.size = data.len() as u64;

        self.stats.writes += 1;
        self.stats.bytes_written += buffer.len() as u64;

        Ok(buffer.len())
    }

    fn lseek(&mut self, fd: u32, offset: i64, whence: u32) -> VfsResult<u64> {
        let file = self.files.get_mut(&fd).ok_or(VfsError::InvalidFd)?;

        let new_pos = match whence {
            0 => {
                if offset < 0 {
                    return Err(VfsError::InvalidSeek);
                }
                offset as u64
            }
            1 => {
                if offset < 0 {
                    file.position.saturating_sub((-offset) as u64)
                } else {
                    file.position.saturating_add(offset as u64)
                }
            }
            2 => {
                if offset < 0 {
                    file.size.saturating_sub((-offset) as u64)
                } else {
                    file.size.saturating_add(offset as u64)
                }
            }
            _ => return Err(VfsError::InvalidSeek),
        };

        file.position = new_pos;
        Ok(new_pos)
    }

    fn get_stats(&self) -> IoStatistics {
        self.stats.clone()
    }

    fn clear_all(&mut self) {
        for (_, file) in self.files.iter_mut() {
            file.secure_clear();
        }
        self.files.clear();
        self.stats = IoStatistics::default();
        self.next_fd.store(RESERVED_FDS, Ordering::SeqCst);
    }
}

static FD_TABLE: RwLock<FileDescriptorTable> = RwLock::new(FileDescriptorTable::new());

pub fn vfs_open(path: &str, flags: OpenFlags) -> VfsResult<u32> {
    FD_TABLE.write().open(path, flags)
}

pub fn vfs_close(fd: u32) -> VfsResult<()> {
    FD_TABLE.write().close(fd)
}

pub fn vfs_read(fd: u32, buffer: &mut [u8]) -> VfsResult<usize> {
    FD_TABLE.write().read(fd, buffer)
}

pub fn vfs_write(fd: u32, buffer: &[u8]) -> VfsResult<usize> {
    FD_TABLE.write().write(fd, buffer)
}

pub fn vfs_lseek(fd: u32, offset: i64, whence: u32) -> VfsResult<u64> {
    FD_TABLE.write().lseek(fd, offset, whence)
}

pub fn vfs_fd_exists(fd: u32) -> bool {
    FD_TABLE.read().files.contains_key(&fd)
}

pub fn vfs_io_stats() -> IoStatistics {
    FD_TABLE.read().get_stats()
}

pub fn clear_fd_table() {
    FD_TABLE.write().clear_all();
    compiler_fence(Ordering::SeqCst);
}

pub fn vfs_open_legacy(path: &str, flags: OpenFlags) -> Result<u32, &'static str> {
    vfs_open(path, flags).map_err(|e| e.as_str())
}

pub fn vfs_close_legacy(fd: u32) -> Result<(), &'static str> {
    vfs_close(fd).map_err(|e| e.as_str())
}

pub fn vfs_read_legacy(fd: u32, buffer: &mut [u8]) -> Result<usize, &'static str> {
    vfs_read(fd, buffer).map_err(|e| e.as_str())
}

pub fn vfs_write_legacy(fd: u32, buffer: &[u8]) -> Result<usize, &'static str> {
    vfs_write(fd, buffer).map_err(|e| e.as_str())
}

pub fn vfs_lseek_legacy(fd: u32, offset: i64, whence: u32) -> Result<u64, &'static str> {
    vfs_lseek(fd, offset, whence).map_err(|e| e.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vfs_error_to_errno() {
        assert_eq!(VfsError::NotFound.to_errno(), -2);
        assert_eq!(VfsError::InvalidFd.to_errno(), -9);
        assert_eq!(VfsError::TooManyOpenFiles.to_errno(), -24);
    }

    #[test]
    fn test_open_flags() {
        let flags = OpenFlags::READ | OpenFlags::WRITE;
        assert!(flags.is_readable());
        assert!(flags.is_writable());
        assert!(flags.contains(OpenFlags::READ));
        assert!(flags.contains(OpenFlags::WRITE));
        assert!(!flags.contains(OpenFlags::CREATE));
    }
}
