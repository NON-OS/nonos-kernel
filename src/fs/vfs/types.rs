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

use alloc::{string::String, vec::Vec};

use super::VfsResult;

pub const MAX_FDS: u32 = 65536;
pub const RESERVED_FDS: u32 = 3;
pub const MAX_PATH_LEN: usize = 4096;
pub const MAX_MOUNTS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileSystemType {
    RamFs,
    CryptoFS,
    TmpFs,
    ProcFs,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    File,
    Directory,
    Symlink,
    Device,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileMode {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    None,
    Lz4,
    Zstd,
}

#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub size: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub file_type: FileType,
    pub mode: u32,
    pub inode: u64,
}

#[derive(Debug, Clone)]
pub struct VfsInode(pub u64);

#[derive(Debug, Clone)]
pub struct FileBuffer {
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CowPageRef {
    pub id: u64,
}

#[derive(Debug, Clone)]
pub struct FileCacheEntry {
    pub inode: VfsInode,
    pub dirty: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum IoOperation {
    Read,
    Write,
    Flush,
    Fsync,
}

#[derive(Debug, Clone)]
pub struct IoRequest {
    pub op: IoOperation,
    pub inode: VfsInode,
    pub offset: u64,
    pub len: usize,
}

#[derive(Debug, Default, Clone)]
pub struct IoStatistics {
    pub reads: u64,
    pub writes: u64,
    pub flushes: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
}

#[derive(Debug, Clone)]
pub struct MountPoint {
    pub mount_path: String,
    pub filesystem: FileSystemType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFlags(u32);

impl OpenFlags {
    pub const READ: OpenFlags = OpenFlags(0x01);
    pub const WRITE: OpenFlags = OpenFlags(0x02);
    pub const CREATE: OpenFlags = OpenFlags(0x04);
    pub const TRUNCATE: OpenFlags = OpenFlags(0x08);
    pub const APPEND: OpenFlags = OpenFlags(0x10);
    pub const EXCLUSIVE: OpenFlags = OpenFlags(0x20);
    pub const NONBLOCK: OpenFlags = OpenFlags(0x40);
    pub const CLOEXEC: OpenFlags = OpenFlags(0x80);

    pub const fn empty() -> Self {
        OpenFlags(0)
    }

    pub const fn from_bits(bits: u32) -> Self {
        OpenFlags(bits)
    }

    pub const fn bits(&self) -> u32 {
        self.0
    }

    pub const fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn is_readable(&self) -> bool {
        self.contains(Self::READ)
    }

    pub const fn is_writable(&self) -> bool {
        self.contains(Self::WRITE)
    }
}

impl core::ops::BitOr for OpenFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        OpenFlags(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for OpenFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

pub trait FileSystemOperations {
    fn sync_metadata(&self);
    fn process_pending_operations(&self, max_ops: usize) -> usize;
}

pub trait DeviceOperations {
    fn flush(&self) -> VfsResult<()>;
}

#[derive(Debug, Default, Clone)]
pub struct VfsStatistics {
    pub mounts: u64,
    pub unmounts: u64,
    pub mkdir_ops: u64,
    pub rmdir_ops: u64,
    pub rename_ops: u64,
    pub unlink_ops: u64,
    pub copy_ops: u64,
}
