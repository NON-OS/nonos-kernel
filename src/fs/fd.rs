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

#![no_std]

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, vec::Vec, string::ToString};
use core::mem::size_of;
use core::sync::atomic::{AtomicI32, Ordering};
use spin::RwLock;

use crate::fs::nonos_filesystem;

// ============================================================================
// CONFIGURATION CONSTANTS (can be overridden at compile-time)
// ============================================================================

/// Maximum number of file descriptors per process
pub const MAX_FD: i32 = 4096;

/// Maximum path length in bytes
pub const MAX_PATH_LEN: usize = 4096;

/// Maximum size for guarded memory copies
pub const MAX_COPY_SIZE: usize = 8 * 1024 * 1024; // 8 MiB

/// Number of reserved file descriptors (stdin, stdout, stderr)
pub const RESERVED_FDS: i32 = 3;

// ============================================================================
// LINUX-COMPATIBLE FILE FLAGS
// ============================================================================

pub const O_RDONLY: i32 = 0o000000;
pub const O_WRONLY: i32 = 0o000001;
pub const O_RDWR: i32 = 0o000002;
pub const O_APPEND: i32 = 0o0002000;
pub const O_CREAT: i32 = 0o0000100;
pub const O_TRUNC: i32 = 0o0001000;
pub const O_NONBLOCK: i32 = 0o0004000;
pub const O_CLOEXEC: i32 = 0o2000000;

// Seek constants
pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

// ============================================================================
// STRUCTURED ERROR HANDLING
// ============================================================================

/// File descriptor operation errors with detailed messages
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdError {
    /// Invalid file descriptor number (out of range or negative)
    InvalidFd,
    /// File descriptor not open
    NotOpen,
    /// Null pointer provided
    NullPointer,
    /// Path too long
    PathTooLong,
    /// Invalid UTF-8 in path
    InvalidUtf8,
    /// File not found
    NotFound,
    /// File already exists
    AlreadyExists,
    /// Permission denied (wrong flags for operation)
    PermissionDenied,
    /// Cannot read from this fd (e.g., stdout)
    NotReadable,
    /// Cannot write to this fd (e.g., stdin)
    NotWritable,
    /// Invalid seek whence parameter
    InvalidWhence,
    /// Cannot perform operation on stdio fd
    StdioOperation,
    /// No file descriptors available
    NoFdsAvailable,
    /// VFS not initialized
    VfsNotInitialized,
    /// Filesystem operation failed
    FsError(&'static str),
    /// Invalid argument
    InvalidArgument,
    /// Buffer too large
    BufferTooLarge,
    /// Operation would block (for non-blocking I/O)
    WouldBlock,
}

impl FdError {
    /// Convert to errno-style negative integer for syscall returns
    pub const fn to_errno(self) -> i32 {
        match self {
            FdError::InvalidFd => -9,        // EBADF
            FdError::NotOpen => -9,          // EBADF
            FdError::NullPointer => -14,     // EFAULT
            FdError::PathTooLong => -36,     // ENAMETOOLONG
            FdError::InvalidUtf8 => -22,     // EINVAL
            FdError::NotFound => -2,         // ENOENT
            FdError::AlreadyExists => -17,   // EEXIST
            FdError::PermissionDenied => -13, // EACCES
            FdError::NotReadable => -9,      // EBADF
            FdError::NotWritable => -9,      // EBADF
            FdError::InvalidWhence => -22,   // EINVAL
            FdError::StdioOperation => -22,  // EINVAL
            FdError::NoFdsAvailable => -24,  // EMFILE
            FdError::VfsNotInitialized => -5, // EIO
            FdError::FsError(_) => -5,       // EIO
            FdError::InvalidArgument => -22, // EINVAL
            FdError::BufferTooLarge => -22,  // EINVAL
            FdError::WouldBlock => -11,      // EAGAIN
        }
    }

    /// Get human-readable error message
    pub const fn as_str(self) -> &'static str {
        match self {
            FdError::InvalidFd => "Invalid file descriptor",
            FdError::NotOpen => "File descriptor not open",
            FdError::NullPointer => "Null pointer",
            FdError::PathTooLong => "Path too long",
            FdError::InvalidUtf8 => "Invalid UTF-8 in path",
            FdError::NotFound => "File not found",
            FdError::AlreadyExists => "File already exists",
            FdError::PermissionDenied => "Permission denied",
            FdError::NotReadable => "File not open for reading",
            FdError::NotWritable => "File not open for writing",
            FdError::InvalidWhence => "Invalid seek whence",
            FdError::StdioOperation => "Cannot perform operation on stdio",
            FdError::NoFdsAvailable => "No file descriptors available",
            FdError::VfsNotInitialized => "VFS not initialized",
            FdError::FsError(msg) => msg,
            FdError::InvalidArgument => "Invalid argument",
            FdError::BufferTooLarge => "Buffer too large",
            FdError::WouldBlock => "Operation would block",
        }
    }
}

// Implement conversion to &'static str for backward compatibility
impl From<FdError> for &'static str {
    fn from(err: FdError) -> Self {
        err.as_str()
    }
}

/// Result type for fd operations
pub type FdResult<T> = Result<T, FdError>;

// ============================================================================
// FILE DESCRIPTOR TABLE STRUCTURE
// ============================================================================

/// Open file descriptor entry with full metadata
#[derive(Debug, Clone)]
struct OpenFile {
    /// Path to the file
    path: String,
    /// Current read/write offset
    offset: usize,
    /// Open flags (O_RDONLY, O_WRONLY, O_RDWR, O_APPEND, etc.)
    flags: i32,
    /// Close-on-exec flag
    cloexec: bool,
}

impl OpenFile {
    fn new(path: String, flags: i32) -> Self {
        let cloexec = (flags & O_CLOEXEC) != 0;
        Self {
            path,
            offset: 0,
            flags: flags & !O_CLOEXEC, // Don't store O_CLOEXEC in flags
            cloexec,
        }
    }

    #[inline]
    fn is_readable(&self) -> bool {
        (self.flags & O_WRONLY) == 0
    }

    #[inline]
    fn is_writable(&self) -> bool {
        (self.flags & O_WRONLY) != 0 || (self.flags & O_RDWR) != 0
    }

    #[inline]
    fn is_append(&self) -> bool {
        (self.flags & O_APPEND) != 0
    }

    #[inline]
    fn is_nonblocking(&self) -> bool {
        (self.flags & O_NONBLOCK) != 0
    }
}

/// Global file descriptor table using RwLock for concurrent read access
static FD_TABLE: RwLock<BTreeMap<i32, OpenFile>> = RwLock::new(BTreeMap::new());

/// Next available file descriptor number
static NEXT_FD: AtomicI32 = AtomicI32::new(RESERVED_FDS);

// ============================================================================
// SAFE MEMORY OPERATIONS
// ============================================================================

/// Safely copy bytes from user space to kernel buffer
///
/// # Safety
/// Caller must ensure `src` points to valid memory of at least `len` bytes.
/// This function validates pointer is non-null and length is reasonable.
#[inline]
pub unsafe fn copy_from_user_ptr(src: *const u8, dst: &mut [u8]) -> FdResult<usize> {
    if src.is_null() {
        return Err(FdError::NullPointer);
    }
    let len = dst.len();
    if len > MAX_COPY_SIZE {
        return Err(FdError::BufferTooLarge);
    }
    core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), len);
    Ok(len)
}

/// Safely copy bytes from kernel buffer to user space
///
/// # Safety
/// Caller must ensure `dst` points to valid writable memory of at least `src.len()` bytes.
#[inline]
pub unsafe fn copy_to_user_ptr(src: &[u8], dst: *mut u8) -> FdResult<usize> {
    if dst.is_null() {
        return Err(FdError::NullPointer);
    }
    let len = src.len();
    if len > MAX_COPY_SIZE {
        return Err(FdError::BufferTooLarge);
    }
    core::ptr::copy_nonoverlapping(src.as_ptr(), dst, len);
    Ok(len)
}

/// Safely read a single byte from user pointer
///
/// # Safety
/// Caller must ensure `ptr` points to valid readable memory.
#[inline]
pub unsafe fn read_user_byte(ptr: *const u8) -> FdResult<u8> {
    if ptr.is_null() {
        return Err(FdError::NullPointer);
    }
    Ok(core::ptr::read(ptr))
}

/// Safely write a single byte to user pointer
///
/// # Safety
/// Caller must ensure `ptr` points to valid writable memory.
#[inline]
pub unsafe fn write_user_byte(ptr: *mut u8, value: u8) -> FdResult<()> {
    if ptr.is_null() {
        return Err(FdError::NullPointer);
    }
    core::ptr::write(ptr, value);
    Ok(())
}

// ============================================================================
// PATH HANDLING
// ============================================================================

/// Convert C-style string pointer to Rust String with validation
pub fn cstr_to_string(ptr: *const u8) -> FdResult<String> {
    if ptr.is_null() {
        return Err(FdError::NullPointer);
    }

    let mut bytes: Vec<u8> = Vec::with_capacity(256);
    let mut off = 0usize;

    loop {
        // Safety: We check null above, and bounds below
        let b = unsafe { core::ptr::read(ptr.add(off)) };
        if b == 0 {
            break;
        }
        bytes.push(b);
        off += 1;
        if off > MAX_PATH_LEN {
            return Err(FdError::PathTooLong);
        }
    }

    core::str::from_utf8(&bytes)
        .map(|s| s.into())
        .map_err(|_| FdError::InvalidUtf8)
}

// ============================================================================
// FD VALIDATION HELPERS
// ============================================================================

/// Validate file descriptor is in valid range
#[inline]
fn validate_fd_range(fd: i32) -> FdResult<()> {
    if fd < 0 || fd > MAX_FD {
        Err(FdError::InvalidFd)
    } else {
        Ok(())
    }
}

/// Check if fd is a stdio descriptor
#[inline]
fn is_stdio(fd: i32) -> bool {
    fd >= 0 && fd < RESERVED_FDS
}

/// Get entry from table (read lock)
fn get_entry_read<F, T>(fd: i32, f: F) -> FdResult<T>
where
    F: FnOnce(&OpenFile) -> FdResult<T>,
{
    validate_fd_range(fd)?;
    if is_stdio(fd) {
        return Err(FdError::StdioOperation);
    }
    let table = FD_TABLE.read();
    let entry = table.get(&fd).ok_or(FdError::NotOpen)?;
    f(entry)
}

/// Get entry from table for mutation (write lock)
fn get_entry_write<F, T>(fd: i32, f: F) -> FdResult<T>
where
    F: FnOnce(&mut OpenFile) -> FdResult<T>,
{
    validate_fd_range(fd)?;
    if is_stdio(fd) {
        return Err(FdError::StdioOperation);
    }
    let mut table = FD_TABLE.write();
    let entry = table.get_mut(&fd).ok_or(FdError::NotOpen)?;
    f(entry)
}

// ============================================================================
// STDIO OPERATIONS
// ============================================================================

/// Write bytes to stdout (VGA display)
fn write_stdout(buf: *const u8, count: usize) -> FdResult<usize> {
    if buf.is_null() {
        return Err(FdError::NullPointer);
    }

    // Safety: Caller guarantees buf is valid for count bytes
    unsafe {
        let slice = core::slice::from_raw_parts(buf, count);
        for &byte in slice {
            if byte == b'\n' {
                crate::arch::x86_64::vga::print("\n");
            } else if byte.is_ascii_graphic() || byte == b' ' {
                let ch = byte as char;
                crate::arch::x86_64::vga::print(&alloc::format!("{}", ch));
            }
        }
    }
    Ok(count)
}

/// Write bytes to stderr (serial console)
fn write_stderr(buf: *const u8, count: usize) -> FdResult<usize> {
    if buf.is_null() {
        return Err(FdError::NullPointer);
    }

    // Safety: Caller guarantees buf is valid for count bytes
    unsafe {
        let slice = core::slice::from_raw_parts(buf, count);
        for &byte in slice {
            crate::arch::x86_64::serial::write_byte(byte);
        }
    }
    Ok(count)
}

/// Read from stdin (keyboard buffer)
fn read_stdin(buf: *mut u8, count: usize) -> FdResult<usize> {
    if buf.is_null() {
        return Err(FdError::NullPointer);
    }
    if count == 0 {
        return Ok(0);
    }

    if let Some(ch) = crate::drivers::keyboard_buffer::read_char() {
        // Safety: buf is valid and non-null checked above
        unsafe { core::ptr::write(buf, ch as u8) }
        Ok(1)
    } else {
        Ok(0)
    }
}

// ============================================================================
// CORE FILE DESCRIPTOR OPERATIONS
// ============================================================================

/// Internal implementation for reading from a file entry
fn read_file_impl(entry: &mut OpenFile, buf: *mut u8, count: usize) -> FdResult<usize> {
    if !entry.is_readable() {
        return Err(FdError::NotReadable);
    }

    let data = crate::fs::read_file(&entry.path)
        .map_err(|e| FdError::FsError(e))?;

    let start = entry.offset.min(data.len());
    let remaining = data.len().saturating_sub(start);
    let to_copy = remaining.min(count);

    if to_copy > 0 {
        // Safety: Caller guarantees buf is valid
        unsafe {
            copy_to_user_ptr(&data[start..start + to_copy], buf)?;
        }
        entry.offset = entry.offset.saturating_add(to_copy);
    }

    Ok(to_copy)
}

/// Internal implementation for reading at offset (pread)
fn read_at_impl(path: &str, buf: *mut u8, count: usize, offset: usize) -> FdResult<usize> {
    let data = crate::fs::read_file(path)
        .map_err(|e| FdError::FsError(e))?;

    let start = offset.min(data.len());
    let remaining = data.len().saturating_sub(start);
    let to_copy = remaining.min(count);

    if to_copy > 0 {
        // Safety: Caller guarantees buf is valid
        unsafe {
            copy_to_user_ptr(&data[start..start + to_copy], buf)?;
        }
    }

    Ok(to_copy)
}

/// Internal implementation for writing to a file entry
fn write_file_impl(entry: &mut OpenFile, buf: *const u8, count: usize) -> FdResult<usize> {
    if !entry.is_writable() {
        return Err(FdError::NotWritable);
    }

    // Read input buffer
    let mut data_to_write = Vec::with_capacity(count);
    data_to_write.resize(count, 0);
    // Safety: buf validity checked by caller
    unsafe {
        copy_from_user_ptr(buf, &mut data_to_write)?;
    }

    // Get existing content
    let mut existing = crate::fs::read_file(&entry.path).unwrap_or_default();

    // Handle O_APPEND
    let write_offset = if entry.is_append() {
        existing.len()
    } else {
        entry.offset
    };

    // Extend file if needed
    if write_offset > existing.len() {
        existing.resize(write_offset, 0);
    }

    // Write data at offset
    let end_offset = write_offset + count;
    if end_offset > existing.len() {
        existing.resize(end_offset, 0);
    }
    existing[write_offset..end_offset].copy_from_slice(&data_to_write);

    // Write back to filesystem
    crate::fs::nonos_filesystem::write_file(&entry.path, &existing)
        .map_err(|e| FdError::FsError(e))?;

    entry.offset = end_offset;
    Ok(count)
}

// ============================================================================
// PUBLIC SYSCALL INTERFACE
// ============================================================================

/// Read from file descriptor (syscall implementation)
/// Returns number of bytes read, or None on error
pub fn read_file_descriptor(fd: i32, buf: *mut u8, count: usize) -> Option<usize> {
    fd_read(fd, buf, count).ok()
}

/// Write to file descriptor (syscall implementation)
/// Returns number of bytes written, or None on error
pub fn write_file_descriptor(fd: i32, buf: *const u8, count: usize) -> Option<usize> {
    fd_write(fd, buf, count).ok()
}

/// Open file (syscall implementation)
pub fn open_file_syscall(pathname: *const u8, flags: i32, _mode: u32) -> Option<i32> {
    fd_open_raw(pathname, flags).ok()
}

/// Open or create file with string path (for internal kernel use)
pub fn open_file_create(path: &str, flags: i32, _mode: u32) -> Option<i32> {
    fd_open(path, flags).ok()
}

/// Close file descriptor (syscall implementation)
pub fn close_file_descriptor(fd: i32) -> bool {
    fd_close(fd).is_ok()
}

// ============================================================================
// STAT STRUCTURES AND OPERATIONS
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct KernelStat {
    mode: u32,      // permission/mode bits
    file_type: u32, // 1=file, 2=dir
    size: u64,      // bytes
    atime: u64,     // access time (ticks)
    mtime: u64,     // mod time (ticks)
    ctime: u64,     // change/creation time (ticks)
}

/// Write stat structure to user buffer
fn write_stat(ptr: *mut u8, st: &KernelStat) -> bool {
    if ptr.is_null() {
        return false;
    }

    // Safety: We're writing a known-sized struct to a user-provided buffer
    // Caller must ensure buffer is large enough
    unsafe {
        let bytes: &[u8] = core::slice::from_raw_parts(
            (st as *const KernelStat) as *const u8,
            size_of::<KernelStat>(),
        );
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
    }
    true
}

/// Stat file (syscall implementation)
pub fn stat_file_syscall(pathname: *const u8, statbuf: *mut u8) -> bool {
    let path = match cstr_to_string(pathname) {
        Ok(p) => p,
        Err(_) => return false,
    };
    stat_path(&path, statbuf).is_ok()
}

/// Stat by path (internal helper)
fn stat_path(path: &str, statbuf: *mut u8) -> FdResult<()> {
    let p = nonos_filesystem::normalize_path(path);

    // Check if directory
    if nonos_filesystem::NONOS_FILESYSTEM.exists(&p) && nonos_filesystem::list_dir(&p).is_ok() {
        let st = KernelStat {
            mode: 0o755,
            file_type: 2,
            size: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
        };
        if write_stat(statbuf, &st) {
            return Ok(());
        }
        return Err(FdError::NullPointer);
    }

    // Check if file
    match nonos_filesystem::NONOS_FILESYSTEM.get_file_info(&p) {
        Ok(info) => {
            let st = KernelStat {
                mode: 0o644,
                file_type: 1,
                size: info.size as u64,
                atime: info.modified,
                mtime: info.modified,
                ctime: info.created,
            };
            if write_stat(statbuf, &st) {
                Ok(())
            } else {
                Err(FdError::NullPointer)
            }
        }
        Err(_) => Err(FdError::NotFound),
    }
}

/// Fstat file descriptor (syscall implementation)
pub fn fstat_file_syscall(fd: i32, statbuf: *mut u8) -> bool {
    fd_fstat(fd, statbuf).is_ok()
}

/// Fstat implementation with proper error handling
pub fn fd_fstat(fd: i32, statbuf: *mut u8) -> FdResult<()> {
    validate_fd_range(fd)?;

    if statbuf.is_null() {
        return Err(FdError::NullPointer);
    }

    // Handle stdio
    if is_stdio(fd) {
        let st = KernelStat {
            mode: if fd == 0 { 0o444 } else { 0o222 },
            file_type: 3, // character device
            size: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
        };
        if write_stat(statbuf, &st) {
            return Ok(());
        }
        return Err(FdError::NullPointer);
    }

    let path = {
        let table = FD_TABLE.read();
        let entry = table.get(&fd).ok_or(FdError::NotOpen)?;
        entry.path.clone()
    };

    stat_path(&path, statbuf)
}

// ============================================================================
// DIRECTORY OPERATIONS
// ============================================================================

/// mkdir (syscall implementation)
pub fn mkdir_syscall(pathname: *const u8) -> Result<(), &'static str> {
    let path = cstr_to_string(pathname).map_err(|e| e.as_str())?;
    crate::fs::nonos_vfs::get_vfs()
        .ok_or("VFS not initialized")?
        .mkdir_all(&path)
}

/// rename (syscall implementation)
pub fn rename_syscall(oldpath: *const u8, newpath: *const u8) -> Result<(), &'static str> {
    let old = cstr_to_string(oldpath).map_err(|e| e.as_str())?;
    let new = cstr_to_string(newpath).map_err(|e| e.as_str())?;
    crate::fs::nonos_vfs::get_vfs()
        .ok_or("VFS not initialized")?
        .rename(&old, &new)
}

/// Remove directory
pub fn rmdir_syscall(pathname: *const u8) -> Result<(), &'static str> {
    if pathname.is_null() {
        return Err("Invalid path");
    }
    let path = cstr_to_string(pathname).map_err(|e| e.as_str())?;
    crate::fs::nonos_vfs::get_vfs()
        .ok_or("VFS not initialized")?
        .rmdir(&path)
}

/// Unlink (syscall implementation)
pub fn unlink_syscall(pathname: *const u8) -> Result<(), &'static str> {
    if pathname.is_null() {
        return Err("Invalid path");
    }
    let path = cstr_to_string(pathname).map_err(|e| e.as_str())?;
    crate::fs::nonos_vfs::get_vfs()
        .ok_or("VFS not initialized")?
        .unlink(&path)
}

/// Sync all filesystem buffers (RAM-only: no-op)
pub fn sync_all() -> Result<(), &'static str> {
    Ok(())
}

// ============================================================================
// LSEEK IMPLEMENTATION
// ============================================================================

/// lseek syscall implementation
pub fn lseek_syscall(fd: i32, offset: i64, whence: i32) -> Result<i64, &'static str> {
    fd_lseek(fd, offset, whence).map_err(|e| e.as_str())
}

/// lseek with FdError
pub fn fd_lseek(fd: i32, offset: i64, whence: i32) -> FdResult<i64> {
    validate_fd_range(fd)?;

    if is_stdio(fd) {
        return Err(FdError::StdioOperation);
    }

    let mut table = FD_TABLE.write();
    let entry = table.get_mut(&fd).ok_or(FdError::NotOpen)?;

    let new_offset = match whence {
        SEEK_SET => {
            if offset < 0 {
                return Err(FdError::InvalidArgument);
            }
            offset as usize
        }
        SEEK_CUR => {
            if offset < 0 {
                entry.offset.saturating_sub((-offset) as usize)
            } else {
                entry.offset.saturating_add(offset as usize)
            }
        }
        SEEK_END => {
            let file_size = nonos_filesystem::NONOS_FILESYSTEM
                .get_file_info(&entry.path)
                .map(|info| info.size)
                .unwrap_or(0);

            if offset < 0 {
                file_size.saturating_sub((-offset) as usize)
            } else {
                file_size.saturating_add(offset as usize)
            }
        }
        _ => return Err(FdError::InvalidWhence),
    };

    entry.offset = new_offset;
    Ok(new_offset as i64)
}

// ============================================================================
// FILE DESCRIPTOR MANAGEMENT
// ============================================================================

/// Check if a file descriptor is valid and open
pub fn fd_is_valid(fd: i32) -> bool {
    if fd < 0 || fd > MAX_FD {
        return false;
    }
    if is_stdio(fd) {
        return true;
    }
    let table = FD_TABLE.read();
    table.contains_key(&fd)
}

/// Open file by path
pub fn fd_open(path: &str, flags: i32) -> FdResult<i32> {
    let normalized = nonos_filesystem::normalize_path(path);
    let exists = nonos_filesystem::exists(&normalized);

    if !exists {
        if (flags & O_CREAT) != 0 {
            nonos_filesystem::create_file(&normalized, &[])
                .map_err(|e| FdError::FsError(e))?;
        } else {
            return Err(FdError::NotFound);
        }
    } else if (flags & O_TRUNC) != 0 {
        nonos_filesystem::write_file(&normalized, &[])
            .map_err(|e| FdError::FsError(e))?;
    }

    // Allocate fd atomically
    let fd = loop {
        let candidate = NEXT_FD.fetch_add(1, Ordering::Relaxed);
        if candidate > MAX_FD {
            // Wrap around and try to find available fd
            NEXT_FD.store(RESERVED_FDS, Ordering::Relaxed);
            let table = FD_TABLE.read();
            for i in RESERVED_FDS..=MAX_FD {
                if !table.contains_key(&i) {
                    break i;
                }
            }
            return Err(FdError::NoFdsAvailable);
        }
        break candidate;
    };

    let mut table = FD_TABLE.write();
    table.insert(fd, OpenFile::new(normalized, flags));
    Ok(fd)
}

/// Open file from raw C string pointer
pub fn fd_open_raw(pathname: *const u8, flags: i32) -> FdResult<i32> {
    let path = cstr_to_string(pathname)?;
    fd_open(&path, flags)
}

/// Close file descriptor
pub fn fd_close(fd: i32) -> FdResult<()> {
    validate_fd_range(fd)?;

    // Cannot close stdio
    if is_stdio(fd) {
        return Ok(()); // Silently succeed for compatibility
    }

    let mut table = FD_TABLE.write();
    if table.remove(&fd).is_some() {
        Ok(())
    } else {
        Err(FdError::NotOpen)
    }
}

/// Set close-on-exec flag
pub fn fd_set_cloexec(fd: i32, cloexec: bool) -> FdResult<()> {
    get_entry_write(fd, |entry| {
        entry.cloexec = cloexec;
        Ok(())
    })
}

/// Get close-on-exec flag
pub fn fd_get_cloexec(fd: i32) -> FdResult<bool> {
    get_entry_read(fd, |entry| Ok(entry.cloexec))
}

/// Write to file descriptor with FdError
pub fn fd_write(fd: i32, buf: *const u8, count: usize) -> FdResult<usize> {
    validate_fd_range(fd)?;

    if buf.is_null() {
        return Err(FdError::NullPointer);
    }

    if count == 0 {
        return Ok(0);
    }

    match fd {
        0 => Err(FdError::NotWritable),
        1 => write_stdout(buf, count),
        2 => write_stderr(buf, count),
        _ => {
            let mut table = FD_TABLE.write();
            let entry = table.get_mut(&fd).ok_or(FdError::NotOpen)?;
            write_file_impl(entry, buf, count)
        }
    }
}

/// Read from file descriptor with FdError
pub fn fd_read(fd: i32, buf: *mut u8, count: usize) -> FdResult<usize> {
    validate_fd_range(fd)?;

    if buf.is_null() {
        return Err(FdError::NullPointer);
    }

    if count == 0 {
        return Ok(0);
    }

    match fd {
        0 => read_stdin(buf, count),
        1 | 2 => Err(FdError::NotReadable),
        _ => {
            let mut table = FD_TABLE.write();
            let entry = table.get_mut(&fd).ok_or(FdError::NotOpen)?;
            read_file_impl(entry, buf, count)
        }
    }
}

/// Read at specific offset without changing fd's offset (pread)
pub fn fd_read_at(fd: i32, buf: *mut u8, count: usize, offset: usize) -> FdResult<usize> {
    validate_fd_range(fd)?;

    if buf.is_null() {
        return Err(FdError::NullPointer);
    }

    if is_stdio(fd) {
        return Err(FdError::StdioOperation);
    }

    let (path, readable) = {
        let table = FD_TABLE.read();
        let entry = table.get(&fd).ok_or(FdError::NotOpen)?;
        (entry.path.clone(), entry.is_readable())
    };

    if !readable {
        return Err(FdError::NotReadable);
    }

    read_at_impl(&path, buf, count, offset)
}

/// Get flags for file descriptor
pub fn fd_get_flags(fd: i32) -> FdResult<i32> {
    validate_fd_range(fd)?;

    match fd {
        0 => Ok(O_RDONLY),
        1 | 2 => Ok(O_WRONLY),
        _ => get_entry_read(fd, |entry| Ok(entry.flags)),
    }
}

/// Set flags for file descriptor (only modifiable flags)
pub fn fd_set_flags(fd: i32, flags: i32) -> FdResult<()> {
    if is_stdio(fd) {
        return Err(FdError::StdioOperation);
    }

    const MODIFIABLE_FLAGS: i32 = O_APPEND | O_NONBLOCK;

    get_entry_write(fd, |entry| {
        entry.flags = (entry.flags & !MODIFIABLE_FLAGS) | (flags & MODIFIABLE_FLAGS);
        Ok(())
    })
}

/// Get path for file descriptor
pub fn fd_get_path(fd: i32) -> FdResult<String> {
    validate_fd_range(fd)?;

    match fd {
        0 => Ok("/dev/stdin".to_string()),
        1 => Ok("/dev/stdout".to_string()),
        2 => Ok("/dev/stderr".to_string()),
        _ => get_entry_read(fd, |entry| Ok(entry.path.clone())),
    }
}

/// Check if file descriptor has data available
pub fn fd_has_data(fd: i32) -> bool {
    if fd < 0 || fd > MAX_FD {
        return false;
    }

    match fd {
        0 => crate::drivers::keyboard_buffer::has_data(),
        1 | 2 => false,
        _ => {
            let table = FD_TABLE.read();
            if let Some(entry) = table.get(&fd) {
                if let Ok(data) = crate::fs::read_file(&entry.path) {
                    entry.offset < data.len()
                } else {
                    false
                }
            } else {
                false
            }
        }
    }
}

/// Check if file descriptor can be written to
pub fn fd_can_write(fd: i32) -> bool {
    if fd < 0 || fd > MAX_FD {
        return false;
    }

    match fd {
        0 => false,
        1 | 2 => true,
        _ => {
            let table = FD_TABLE.read();
            table.get(&fd).map(|e| e.is_writable()).unwrap_or(false)
        }
    }
}

/// Check if remote end is closed (for pipes/sockets)
pub fn fd_is_closed_remote(fd: i32) -> bool {
    if fd < 0 || fd > MAX_FD {
        return true;
    }

    match fd {
        0 | 1 | 2 => false,
        _ => {
            let table = FD_TABLE.read();
            !table.contains_key(&fd)
        }
    }
}

/// Get number of bytes available for reading
pub fn fd_bytes_available(fd: i32) -> FdResult<usize> {
    validate_fd_range(fd)?;

    match fd {
        0 => Ok(crate::drivers::keyboard_buffer::available_count()),
        1 | 2 => Err(FdError::NotReadable),
        _ => {
            let table = FD_TABLE.read();
            let entry = table.get(&fd).ok_or(FdError::NotOpen)?;

            if !entry.is_readable() {
                return Err(FdError::NotReadable);
            }

            let data = crate::fs::read_file(&entry.path)
                .map_err(|e| FdError::FsError(e))?;
            Ok(data.len().saturating_sub(entry.offset))
        }
    }
}

/// Set non-blocking mode
pub fn fd_set_nonblocking(fd: i32, nonblocking: bool) -> FdResult<()> {
    if is_stdio(fd) {
        return Ok(()); // Accept for compatibility
    }

    get_entry_write(fd, |entry| {
        if nonblocking {
            entry.flags |= O_NONBLOCK;
        } else {
            entry.flags &= !O_NONBLOCK;
        }
        Ok(())
    })
}

/// Duplicate file descriptor to lowest available fd >= min_fd
pub fn fd_dup_min(old_fd: i32, min_fd: i32) -> FdResult<i32> {
    validate_fd_range(old_fd)?;

    if min_fd < 0 {
        return Err(FdError::InvalidArgument);
    }

    // Find lowest available fd >= min_fd
    let find_free_fd = |min: i32| -> FdResult<i32> {
        let table = FD_TABLE.read();
        for candidate in min..=MAX_FD {
            if candidate >= RESERVED_FDS && !table.contains_key(&candidate) {
                return Ok(candidate);
            }
        }
        Err(FdError::NoFdsAvailable)
    };

    let new_fd = find_free_fd(min_fd.max(RESERVED_FDS))?;

    // Handle stdio duplication
    if is_stdio(old_fd) {
        let (path, flags) = match old_fd {
            0 => ("/dev/stdin", O_RDONLY),
            1 => ("/dev/stdout", O_WRONLY),
            2 => ("/dev/stderr", O_WRONLY),
            _ => return Err(FdError::InvalidFd),
        };

        let mut table = FD_TABLE.write();
        table.insert(new_fd, OpenFile::new(path.to_string(), flags));
        return Ok(new_fd);
    }

    // Clone regular fd entry
    let entry = {
        let table = FD_TABLE.read();
        table.get(&old_fd).ok_or(FdError::NotOpen)?.clone()
    };

    let mut table = FD_TABLE.write();
    table.insert(new_fd, entry);
    Ok(new_fd)
}

/// Duplicate file descriptor (dup)
pub fn fd_dup(old_fd: i32) -> FdResult<i32> {
    fd_dup_min(old_fd, RESERVED_FDS)
}

/// Duplicate to specific fd (dup2)
pub fn fd_dup2(old_fd: i32, new_fd: i32) -> FdResult<i32> {
    validate_fd_range(old_fd)?;
    validate_fd_range(new_fd)?;

    if old_fd == new_fd {
        // Check old_fd is valid
        if !fd_is_valid(old_fd) {
            return Err(FdError::NotOpen);
        }
        return Ok(new_fd);
    }

    // Close new_fd if open (ignore errors)
    let _ = fd_close(new_fd);

    // Handle stdio duplication
    if is_stdio(old_fd) {
        let (path, flags) = match old_fd {
            0 => ("/dev/stdin", O_RDONLY),
            1 => ("/dev/stdout", O_WRONLY),
            2 => ("/dev/stderr", O_WRONLY),
            _ => return Err(FdError::InvalidFd),
        };

        if !is_stdio(new_fd) {
            let mut table = FD_TABLE.write();
            table.insert(new_fd, OpenFile::new(path.to_string(), flags));
        }
        return Ok(new_fd);
    }

    // Clone regular fd entry
    let entry = {
        let table = FD_TABLE.read();
        table.get(&old_fd).ok_or(FdError::NotOpen)?.clone()
    };

    if !is_stdio(new_fd) {
        let mut table = FD_TABLE.write();
        table.insert(new_fd, entry);
    }

    Ok(new_fd)
}

/// Alias for fd_can_write
pub fn fd_is_writable(fd: i32) -> bool {
    fd_can_write(fd)
}

/// Truncate file to specified length
pub fn fd_truncate(fd: i32, length: usize) -> FdResult<()> {
    validate_fd_range(fd)?;

    if is_stdio(fd) {
        return Err(FdError::StdioOperation);
    }

    let path = {
        let table = FD_TABLE.read();
        let entry = table.get(&fd).ok_or(FdError::NotOpen)?;

        if !entry.is_writable() {
            return Err(FdError::NotWritable);
        }

        entry.path.clone()
    };

    // Read and truncate/extend
    let mut data = crate::fs::read_file(&path).unwrap_or_default();
    data.resize(length, 0);

    crate::fs::nonos_filesystem::write_file(&path, &data)
        .map_err(|e| FdError::FsError(e))
}

/// Close all F.D with cloexec flag set, during exec() to clean up inherited fds
pub fn fd_close_cloexec() {
    let fds_to_close: Vec<i32> = {
        let table = FD_TABLE.read();
        table.iter()
            .filter(|(_, entry)| entry.cloexec)
            .map(|(fd, _)| *fd)
            .collect()
    };

    let mut table = FD_TABLE.write();
    for fd in fds_to_close {
        table.remove(&fd);
    }
}

pub fn fd_get_offset(fd: i32) -> FdResult<usize> {
    get_entry_read(fd, |entry| Ok(entry.offset))
}

pub fn fd_stats() -> (usize, i32) {
    let table = FD_TABLE.read();
    let count = table.len();
    let next = NEXT_FD.load(Ordering::Relaxed);
    (count, next)
}

// ============================================================================
// BACKWARD COMPATIBILITY (deprecated functions)
// ============================================================================

#[deprecated(note = "Use fd_read instead")]
pub fn fd_read_legacy(fd: i32, buf: *mut u8, count: usize) -> Result<usize, &'static str> {
    fd_read(fd, buf, count).map_err(|e| e.as_str())
}

#[deprecated(note = "Use fd_write instead")]
pub fn fd_write_legacy(fd: i32, buf: *const u8, count: usize) -> Result<usize, &'static str> {
    fd_write(fd, buf, count).map_err(|e| e.as_str())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fd_error_to_errno() {
        assert_eq!(FdError::InvalidFd.to_errno(), -9);
        assert_eq!(FdError::NotFound.to_errno(), -2);
        assert_eq!(FdError::PermissionDenied.to_errno(), -13);
    }

    #[test]
    fn test_open_file_flags() {
        let entry = OpenFile::new("/test".to_string(), O_RDWR | O_APPEND | O_CLOEXEC);
        assert!(entry.is_readable());
        assert!(entry.is_writable());
        assert!(entry.is_append());
        assert!(entry.cloexec);
        // O_CLOEXEC should not be stored in flags
        assert_eq!(entry.flags & O_CLOEXEC, 0);
    }

    #[test]
    fn test_validate_fd_range() {
        assert!(validate_fd_range(0).is_ok());
        assert!(validate_fd_range(MAX_FD).is_ok());
        assert!(validate_fd_range(-1).is_err());
        assert!(validate_fd_range(MAX_FD + 1).is_err());
    }
}
