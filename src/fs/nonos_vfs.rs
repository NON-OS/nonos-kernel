// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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

//! NØNOS Virtual File System (VFS) layer. w/:
//! - Unified file access across multiple filesystem types
//! - File descriptor management for POSIX-like syscalls
//! - Mount point management
//! - Secure memory zeroization for privacy

#![no_std]

extern crate alloc;

use alloc::{string::String, string::ToString, vec::Vec, collections::BTreeMap, format};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering, compiler_fence};
use spin::{Once, RwLock};

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================

/// Maximum number of open file descriptors
pub const MAX_FDS: u32 = 65536;

/// Reserved file descriptors (stdin=0, stdout=1, stderr=2)
pub const RESERVED_FDS: u32 = 3;

/// Maximum path length
pub const MAX_PATH_LEN: usize = 4096;

/// Maximum number of mount points
pub const MAX_MOUNTS: usize = 256;

// ============================================================================
// STRUCTURED ERROR HANDLING
// ============================================================================

/// VFS operation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsError {
    /// VFS not initialized
    NotInitialized,
    /// File not found
    NotFound,
    /// File already exists
    AlreadyExists,
    /// Path too long
    PathTooLong,
    /// Invalid path
    InvalidPath,
    /// Too many open files
    TooManyOpenFiles,
    /// Invalid file descriptor
    InvalidFd,
    /// File not open for reading
    NotReadable,
    /// File not open for writing
    NotWritable,
    /// Invalid seek position
    InvalidSeek,
    /// Directory not empty
    DirectoryNotEmpty,
    /// Not a directory
    NotADirectory,
    /// Is a directory
    IsADirectory,
    /// Permission denied
    PermissionDenied,
    /// Filesystem error
    FsError(&'static str),
    /// I/O error
    IoError(&'static str),
}

impl VfsError {
    /// Convert to errno-style negative integer
    pub const fn to_errno(self) -> i32 {
        match self {
            VfsError::NotInitialized => -5,    // EIO
            VfsError::NotFound => -2,          // ENOENT
            VfsError::AlreadyExists => -17,    // EEXIST
            VfsError::PathTooLong => -36,      // ENAMETOOLONG
            VfsError::InvalidPath => -22,      // EINVAL
            VfsError::TooManyOpenFiles => -24, // EMFILE
            VfsError::InvalidFd => -9,         // EBADF
            VfsError::NotReadable => -9,       // EBADF
            VfsError::NotWritable => -9,       // EBADF
            VfsError::InvalidSeek => -22,      // EINVAL
            VfsError::DirectoryNotEmpty => -39, // ENOTEMPTY
            VfsError::NotADirectory => -20,    // ENOTDIR
            VfsError::IsADirectory => -21,     // EISDIR
            VfsError::PermissionDenied => -13, // EACCES
            VfsError::FsError(_) => -5,        // EIO
            VfsError::IoError(_) => -5,        // EIO
        }
    }

    /// Get human-readable error message
    pub const fn as_str(self) -> &'static str {
        match self {
            VfsError::NotInitialized => "VFS not initialized",
            VfsError::NotFound => "File not found",
            VfsError::AlreadyExists => "File already exists",
            VfsError::PathTooLong => "Path too long",
            VfsError::InvalidPath => "Invalid path",
            VfsError::TooManyOpenFiles => "Too many open files",
            VfsError::InvalidFd => "Invalid file descriptor",
            VfsError::NotReadable => "File not open for reading",
            VfsError::NotWritable => "File not open for writing",
            VfsError::InvalidSeek => "Invalid seek position",
            VfsError::DirectoryNotEmpty => "Directory not empty",
            VfsError::NotADirectory => "Not a directory",
            VfsError::IsADirectory => "Is a directory",
            VfsError::PermissionDenied => "Permission denied",
            VfsError::FsError(msg) => msg,
            VfsError::IoError(msg) => msg,
        }
    }
}

impl From<VfsError> for &'static str {
    fn from(err: VfsError) -> Self {
        err.as_str()
    }
}

impl From<super::nonos_filesystem::FsError> for VfsError {
    fn from(err: super::nonos_filesystem::FsError) -> Self {
        VfsError::FsError(err.as_str())
    }
}

/// Result type for VFS operations
pub type VfsResult<T> = Result<T, VfsError>;

// ============================================================================
// SECURE MEMORY OPERATIONS
// ============================================================================

/// Securely zeroize a byte slice
#[inline]
fn secure_zeroize(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Securely zeroize a String's backing buffer
#[inline]
fn secure_zeroize_string(s: &mut String) {
    // Safety: We're zeroing the string's buffer before clearing it
    let bytes = unsafe { s.as_bytes_mut() };
    secure_zeroize(bytes);
    s.clear();
}

// ============================================================================
// FILESYSTEM TYPES
// ============================================================================

/// Supported filesystem types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileSystemType {
    /// RAM-based filesystem
    RamFs,
    /// Encrypted filesystem
    CryptoFS,
    /// Temporary filesystem
    TmpFs,
    /// Process information pseudo-filesystem
    ProcFs,
    /// Unknown type
    Unknown,
}

/// File type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    File,
    Directory,
    Symlink,
    Device,
}

/// File access mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileMode {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

/// Compression algorithm (for future use)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    None,
    Lz4,
    Zstd,
}

// ============================================================================
// FILE METADATA
// ============================================================================

/// File metadata structure
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

/// VFS inode wrapper
#[derive(Debug, Clone)]
pub struct VfsInode(pub u64);

/// File buffer for I/O operations
#[derive(Debug, Clone)]
pub struct FileBuffer {
    pub data: Vec<u8>,
}

/// Copy-on-write page reference
#[derive(Debug, Clone)]
pub struct CowPageRef {
    pub id: u64,
}

/// File cache entry
#[derive(Debug, Clone)]
pub struct FileCacheEntry {
    pub inode: VfsInode,
    pub dirty: bool,
}

/// I/O operation type
#[derive(Debug, Clone, Copy)]
pub enum IoOperation {
    Read,
    Write,
    Flush,
    Fsync,
}

/// I/O request
#[derive(Debug, Clone)]
pub struct IoRequest {
    pub op: IoOperation,
    pub inode: VfsInode,
    pub offset: u64,
    pub len: usize,
}

/// I/O statistics
#[derive(Debug, Default, Clone)]
pub struct IoStatistics {
    pub reads: u64,
    pub writes: u64,
    pub flushes: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
}

/// Mount point
#[derive(Debug, Clone)]
pub struct MountPoint {
    pub mount_path: String,
    pub filesystem: FileSystemType,
}

// ============================================================================
// OPEN FLAGS (bitflags)
// ============================================================================

/// Open flags for file operations
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

    pub const fn empty() -> Self {
        OpenFlags(0)
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

// ============================================================================
// OPEN FILE HANDLE
// ============================================================================

/// Open file handle
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

// ============================================================================
// FILE DESCRIPTOR TABLE
// ============================================================================

/// File descriptor table
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
        // Find lowest available fd
        for fd in RESERVED_FDS..MAX_FDS {
            if !self.files.contains_key(&fd) {
                return Ok(fd);
            }
        }
        Err(VfsError::TooManyOpenFiles)
    }

    fn open(&mut self, path: &str, flags: OpenFlags) -> VfsResult<u32> {
        // Validate path
        if path.is_empty() {
            return Err(VfsError::InvalidPath);
        }
        if path.len() > MAX_PATH_LEN {
            return Err(VfsError::PathTooLong);
        }

        let fd = self.allocate_fd()?;

        // Check if file exists
        let file_exists = super::nonos_filesystem::NONOS_FILESYSTEM.exists(path);

        if !file_exists && !flags.contains(OpenFlags::CREATE) {
            return Err(VfsError::NotFound);
        }

        // Create file if needed
        if !file_exists && flags.contains(OpenFlags::CREATE) {
            super::nonos_filesystem::NONOS_FILESYSTEM.create_file(path, b"")?;
        }

        // Handle truncation
        if file_exists && flags.contains(OpenFlags::TRUNCATE) && flags.contains(OpenFlags::WRITE) {
            super::nonos_filesystem::NONOS_FILESYSTEM.write_file(path, b"")?;
        }

        // Get file size
        let size = super::nonos_filesystem::NONOS_FILESYSTEM.read_file(path)
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

        let data = super::nonos_filesystem::NONOS_FILESYSTEM.read_file(&file.path)?;
        let pos = file.position as usize;

        if pos >= data.len() {
            return Ok(0); // EOF
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

        // Read current file content
        let mut data = super::nonos_filesystem::NONOS_FILESYSTEM.read_file(&file.path)
            .unwrap_or_else(|_| Vec::new());

        let pos = file.position as usize;

        // Extend file if writing past current size
        if pos > data.len() {
            data.resize(pos, 0);
        }

        // Write data at position
        if pos + buffer.len() > data.len() {
            data.resize(pos + buffer.len(), 0);
        }

        data[pos..pos + buffer.len()].copy_from_slice(buffer);

        // Write back to filesystem
        super::nonos_filesystem::NONOS_FILESYSTEM.write_file(&file.path, &data)?;

        file.position += buffer.len() as u64;
        file.size = data.len() as u64;

        self.stats.writes += 1;
        self.stats.bytes_written += buffer.len() as u64;

        Ok(buffer.len())
    }

    fn lseek(&mut self, fd: u32, offset: i64, whence: u32) -> VfsResult<u64> {
        let file = self.files.get_mut(&fd).ok_or(VfsError::InvalidFd)?;

        let new_pos = match whence {
            0 => { // SEEK_SET
                if offset < 0 {
                    return Err(VfsError::InvalidSeek);
                }
                offset as u64
            }
            1 => { // SEEK_CUR
                if offset < 0 {
                    file.position.saturating_sub((-offset) as u64)
                } else {
                    file.position.saturating_add(offset as u64)
                }
            }
            2 => { // SEEK_END
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

// ============================================================================
// GLOBAL FILE DESCRIPTOR TABLE
// ============================================================================

static FD_TABLE: RwLock<FileDescriptorTable> = RwLock::new(FileDescriptorTable::new());

/// Open a file and return a file descriptor
pub fn vfs_open(path: &str, flags: OpenFlags) -> VfsResult<u32> {
    FD_TABLE.write().open(path, flags)
}

/// Close a file descriptor
pub fn vfs_close(fd: u32) -> VfsResult<()> {
    FD_TABLE.write().close(fd)
}

/// Read from a file descriptor
pub fn vfs_read(fd: u32, buffer: &mut [u8]) -> VfsResult<usize> {
    FD_TABLE.write().read(fd, buffer)
}

/// Write to a file descriptor
pub fn vfs_write(fd: u32, buffer: &[u8]) -> VfsResult<usize> {
    FD_TABLE.write().write(fd, buffer)
}

/// Seek within a file
pub fn vfs_lseek(fd: u32, offset: i64, whence: u32) -> VfsResult<u64> {
    FD_TABLE.write().lseek(fd, offset, whence)
}

/// Check if a file descriptor exists
pub fn vfs_fd_exists(fd: u32) -> bool {
    FD_TABLE.read().files.contains_key(&fd)
}

/// Get I/O statistics
pub fn vfs_io_stats() -> IoStatistics {
    FD_TABLE.read().get_stats()
}

// ============================================================================
// FILESYSTEM OPERATIONS TRAITS
// ============================================================================

pub trait FileSystemOperations {
    fn sync_metadata(&self);
    fn process_pending_operations(&self, max_ops: usize) -> usize;
}

pub trait DeviceOperations {
    fn flush(&self) -> VfsResult<()>;
}

// ============================================================================
// VFS STATISTICS
// ============================================================================

/// VFS statistics
#[derive(Debug, Default, Clone)]
pub struct VfsStatistics {
    pub mounts: u64,
    pub unmounts: u64,
    pub mkdir_ops: u64,
    pub rmdir_ops: u64,
    pub rename_ops: u64,
    pub unlink_ops: u64,
}

// ============================================================================
// VIRTUAL FILE SYSTEM
// ============================================================================

/// VFS internal state
struct VirtualFileSystemInner {
    mounts: Vec<MountPoint>,
    pending_ops: usize,
    io_stats: IoStatistics,
    vfs_stats: VfsStatistics,
}

/// Virtual File System
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
        // RAM-only: nothing to persist
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
                mount_path: mount_path.into(),
                filesystem: fs_type,
            });
            g.vfs_stats.mounts += 1;
        }
    }

    pub fn mounts(&self) -> Vec<MountPoint> {
        self.inner.lock().mounts.clone()
    }

    /// Create directories recursively (mkdir -p equivalent)
    pub fn mkdir_all(&self, path: &str) -> VfsResult<()> {
        // In RAM-only ZeroState mode, directories are implicit from file paths
        let marker_path = if path.ends_with('/') {
            format!("{}.dir", path.trim_end_matches('/'))
        } else {
            format!("{}/.dir", path)
        };

        // Check if already exists
        if super::nonos_filesystem::NONOS_FILESYSTEM.exists(&marker_path) {
            return Ok(());
        }

        // Create the directory marker
        super::nonos_filesystem::NONOS_FILESYSTEM.create_file(&marker_path, b"")?;

        self.inner.lock().vfs_stats.mkdir_ops += 1;
        Ok(())
    }

    /// Rename a file or directory
    pub fn rename(&self, old_path: &str, new_path: &str) -> VfsResult<()> {
        // Read the file contents
        let data = super::nonos_filesystem::NONOS_FILESYSTEM.read_file(old_path)?;

        // Create at new location
        super::nonos_filesystem::NONOS_FILESYSTEM.create_file(new_path, &data)?;

        // Delete the old file
        super::nonos_filesystem::NONOS_FILESYSTEM.delete_file(old_path)?;

        self.inner.lock().vfs_stats.rename_ops += 1;
        Ok(())
    }

    /// Remove a directory (must be empty)
    pub fn rmdir(&self, path: &str) -> VfsResult<()> {
        // Check if directory is empty
        let files = super::nonos_filesystem::NONOS_FILESYSTEM.list_files();
        let prefix = if path.ends_with('/') {
            path.to_string()
        } else {
            format!("{}/", path)
        };

        // Count files in this directory (excluding .dir marker)
        let entries: Vec<_> = files.iter()
            .filter(|f| f.starts_with(&prefix) && !f.ends_with("/.dir"))
            .collect();

        if !entries.is_empty() {
            return Err(VfsError::DirectoryNotEmpty);
        }

        // Remove directory marker
        let marker_path = if path.ends_with('/') {
            format!("{}.dir", path.trim_end_matches('/'))
        } else {
            format!("{}/.dir", path)
        };

        let _ = super::nonos_filesystem::NONOS_FILESYSTEM.delete_file(&marker_path);

        self.inner.lock().vfs_stats.rmdir_ops += 1;
        Ok(())
    }

    /// Unlink (delete) a file
    pub fn unlink(&self, path: &str) -> VfsResult<()> {
        super::nonos_filesystem::NONOS_FILESYSTEM.delete_file(path)?;
        self.inner.lock().vfs_stats.unlink_ops += 1;
        Ok(())
    }

    /// Read entire file contents
    pub fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
        super::nonos_filesystem::NONOS_FILESYSTEM.read_file(path)
            .map_err(VfsError::from)
    }

    /// Write entire file contents (create or overwrite)
    pub fn write_file(&self, path: &str, data: &[u8]) -> VfsResult<()> {
        if super::nonos_filesystem::NONOS_FILESYSTEM.exists(path) {
            super::nonos_filesystem::NONOS_FILESYSTEM.write_file(path, data)?;
        } else {
            super::nonos_filesystem::NONOS_FILESYSTEM.create_file(path, data)?;
        }
        Ok(())
    }

    /// Check if a file exists
    pub fn exists(&self, path: &str) -> bool {
        super::nonos_filesystem::NONOS_FILESYSTEM.exists(path)
    }

    /// List directory contents
    pub fn list_dir(&self, path: &str) -> VfsResult<Vec<String>> {
        super::nonos_filesystem::list_dir(path).map_err(VfsError::from)
    }

    /// Get file metadata
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

        // Compute inode from path hash
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

    /// Get VFS statistics
    pub fn stats(&self) -> VfsStatistics {
        self.inner.lock().vfs_stats.clone()
    }

    /// Clear all VFS state
    pub fn clear_all(&self) {
        let mut inner = self.inner.lock();

        // Zero out mount paths
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

// ============================================================================
// GLOBAL VFS INSTANCE
// ============================================================================

static VFS: Once<VirtualFileSystem> = Once::new();

/// Initialize the VFS
pub fn init_vfs() {
    VFS.call_once(|| {
        let vfs = VirtualFileSystem::new();
        vfs.mount("/", FileSystemType::RamFs);
        vfs
    });
}

/// Get reference to global VFS
pub fn get_vfs() -> Option<&'static VirtualFileSystem> {
    VFS.get()
}

/// Get mutable reference to global VFS (interior mutability)
pub fn get_vfs_mut() -> Option<&'static VirtualFileSystem> {
    VFS.get()
}

/// Clear all VFS caches for ZeroState privacy wipe
pub fn clear_vfs_caches() {
    // Clear file descriptor table
    FD_TABLE.write().clear_all();

    // Clear VFS state
    if let Some(vfs) = VFS.get() {
        vfs.clear_all();
    }

    compiler_fence(Ordering::SeqCst);
}

// ============================================================================
// LEGACY API (backward compatibility)
// ============================================================================

/// Open file (legacy interface)
pub fn vfs_open_legacy(path: &str, flags: OpenFlags) -> Result<u32, &'static str> {
    vfs_open(path, flags).map_err(|e| e.as_str())
}

/// Close file (legacy interface)
pub fn vfs_close_legacy(fd: u32) -> Result<(), &'static str> {
    vfs_close(fd).map_err(|e| e.as_str())
}

/// Read file (legacy interface)
pub fn vfs_read_legacy(fd: u32, buffer: &mut [u8]) -> Result<usize, &'static str> {
    vfs_read(fd, buffer).map_err(|e| e.as_str())
}

/// Write file (legacy interface)
pub fn vfs_write_legacy(fd: u32, buffer: &[u8]) -> Result<usize, &'static str> {
    vfs_write(fd, buffer).map_err(|e| e.as_str())
}

/// Seek (legacy interface)
pub fn vfs_lseek_legacy(fd: u32, offset: i64, whence: u32) -> Result<u64, &'static str> {
    vfs_lseek(fd, offset, whence).map_err(|e| e.as_str())
}

// ============================================================================
// TESTS
// ============================================================================

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
