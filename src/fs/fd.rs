#![no_std]

extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};
use core::mem::size_of;
use core::sync::atomic::{AtomicI32, Ordering};
use spin::Mutex;

use crate::fs::nonos_filesystem;

// Minimal Linux-like flags
const O_RDONLY: i32 = 0o000000;
const O_WRONLY: i32 = 0o000001;
const O_RDWR: i32 = 0o000002;
const O_APPEND: i32 = 0o0002000;
const O_CREAT: i32 = 0o0000100;
const O_TRUNC: i32 = 0o0001000;

#[derive(Debug, Clone)]
struct OpenFile {
    path: alloc::string::String,
    offset: usize,
    flags: i32,
}

static FD_TABLE: Mutex<BTreeMap<i32, OpenFile>> = Mutex::new(BTreeMap::new());
static NEXT_FD: AtomicI32 = AtomicI32::new(3); // 0,1,2 reserved

fn is_readable(flags: i32) -> bool {
    flags & O_WRONLY == 0
}

fn is_writable(flags: i32) -> bool {
    (flags & O_WRONLY) != 0 || (flags & O_RDWR) != 0
}

pub fn cstr_to_string(ptr: *const u8) -> Result<alloc::string::String, &'static str> {
    if ptr.is_null() {
        return Err("Null pointer");
    }
    let mut bytes: Vec<u8> = Vec::new();
    let mut off = 0usize;
    loop {
        let b = unsafe { core::ptr::read(ptr.add(off)) };
        if b == 0 {
            break;
        }
        bytes.push(b);
        if off > 4096 {
            return Err("Path too long");
        }
        off += 1;
    }
    core::str::from_utf8(&bytes)
        .map(|s| s.to_string())
        .map_err(|_| "Invalid UTF-8 in path")
}

/// Read from file descriptor (syscall implementation)
pub fn read_file_descriptor(fd: i32, buf: *mut u8, count: usize) -> Option<usize> {
    if fd < 0 || fd > 4096 || buf.is_null() {
        return None;
    }

    match fd {
        0 => {
            if count == 0 {
                return Some(0);
            }
            if let Some(ch) = crate::drivers::keyboard_buffer::read_char() {
                unsafe { core::ptr::write(buf, ch as u8) }
                Some(1)
            } else {
                Some(0)
            }
        }
        1 | 2 => None, // stdout/stderr not readable
        _ => {
            let mut table = FD_TABLE.lock();
            let entry = table.get_mut(&fd)?;

            if !is_readable(entry.flags) {
                return None;
            }

            let data = match crate::fs::read_file(&entry.path) {
                Ok(d) => d,
                Err(_) => return None,
            };
            let start = entry.offset.min(data.len());
            let remaining = data.len().saturating_sub(start);
            let to_copy = remaining.min(count);
            unsafe {
                core::ptr::copy_nonoverlapping(data[start..start + to_copy].as_ptr(), buf, to_copy);
            }
            entry.offset = entry.offset.saturating_add(to_copy);
            Some(to_copy)
        }
    }
}

/// Write to file descriptor (syscall implementation)
pub fn write_file_descriptor(fd: i32, buf: *const u8, count: usize) -> Option<usize> {
    if fd < 0 || fd > 4096 || count == 0 || buf.is_null() {
        return None;
    }

    match fd {
        1 => {
            // stdout - write to VGA
            unsafe {
                let slice = core::slice::from_raw_parts(buf, count);
                for &byte in slice {
                    if byte == b'\n' {
                        crate::arch::x86_64::vga::print("\n");
                    } else if byte.is_ascii_graphic() || byte == b' ' {
                        let ch = byte as char;
                        crate::arch::x86_64::vga::print(&ch.to_string());
                    }
                }
            }
            Some(count)
        }
        2 => {
            // stderr - write to serial
            unsafe {
                let slice = core::slice::from_raw_parts(buf, count);
                for &byte in slice {
                    crate::arch::x86_64::serial::write_byte(byte);
                }
            }
            Some(count)
        }
        _ => {
            let mut table = FD_TABLE.lock();
            let entry = table.get_mut(&fd)?;

            if !is_writable(entry.flags) {
                return None;
            }

            // Read existing content
            let mut data = match nonos_filesystem::read_file(&entry.path) {
                Ok(d) => d,
                Err(_) => Vec::new(),
            };

            // Handle O_APPEND
            if entry.flags & O_APPEND != 0 {
                entry.offset = data.len();
            }

            // Ensure capacity up to current offset
            if entry.offset > data.len() {
                data.resize(entry.offset, 0);
            }

            // Copy in bytes
            let to_copy = count;
            unsafe {
                let slice = core::slice::from_raw_parts(buf, to_copy);
                if entry.offset + to_copy > data.len() {
                    data.resize(entry.offset + to_copy, 0);
                }
                data[entry.offset..entry.offset + to_copy].copy_from_slice(slice);
            }

            // Write back
            if nonos_filesystem::write_file(&entry.path, &data).is_err() {
                return None;
            }
            entry.offset = entry.offset.saturating_add(to_copy);
            Some(to_copy)
        }
    }
}

/// Open file (syscall implementation)
pub fn open_file_syscall(pathname: *const u8, flags: i32, _mode: u32) -> Option<i32> {
    let path = cstr_to_string(pathname).ok()?;
    let path = nonos_filesystem::normalize_path(&path);

    let exists = nonos_filesystem::exists(&path);
    if !exists {
        if flags & O_CREAT != 0 {
            if nonos_filesystem::create_file(&path, &[]).is_err() {
                return None;
            }
        } else {
            return None;
        }
    } else if flags & O_TRUNC != 0 {
        if nonos_filesystem::write_file(&path, &[]).is_err() {
            return None;
        }
    }

    let fd = NEXT_FD.fetch_add(1, Ordering::Relaxed);
    let mut table = FD_TABLE.lock();
    table.insert(fd, OpenFile { path, offset: 0, flags });
    Some(fd)
}

/// Close file descriptor (syscall implementation)
pub fn close_file_descriptor(fd: i32) -> bool {
    if fd < 0 || fd > 4096 {
        return false;
    }
    let mut table = FD_TABLE.lock();
    table.remove(&fd).is_some()
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KernelStat {
    // Minimal fixed layout for ZeroState
    mode: u32,    // permission/mode bits (unused -> 0)
    file_type: u32, // 1=file, 2=dir
    size: u64,    // bytes
    atime: u64,   // access time (ticks)
    mtime: u64,   // mod time (ticks)
    ctime: u64,   // change/creation time (ticks)
}

fn write_stat(ptr: *mut u8, st: &KernelStat) -> bool {
    if ptr.is_null() {
        return false;
    }
    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            (st as *const KernelStat) as *const u8,
            size_of::<KernelStat>(),
        )
    };
    unsafe {
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
    let p = nonos_filesystem::normalize_path(&path);
    // Directory?
    if nonos_filesystem::NONOS_FILESYSTEM.exists(&p) && !nonos_filesystem::list_dir(&p).is_err() {
        let st = KernelStat {
            mode: 0,
            file_type: 2,
            size: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
        };
        return write_stat(statbuf, &st);
    }

    // File
    match nonos_filesystem::NONOS_FILESYSTEM.get_file_info(&p) {
        Ok(info) => {
            let st = KernelStat {
                mode: 0,
                file_type: 1,
                size: info.size as u64,
                atime: info.modified, // no separate atime in RAM-only
                mtime: info.modified,
                ctime: info.created,
            };
            write_stat(statbuf, &st)
        }
        Err(_) => false,
    }
}

/// Fstat file descriptor (syscall implementation)
pub fn fstat_file_syscall(fd: i32, statbuf: *mut u8) -> bool {
    if fd < 0 || fd > 4096 || statbuf.is_null() {
        return false;
    }
    let table = FD_TABLE.lock();
    let entry = match table.get(&fd) {
        Some(e) => e,
        None => return false,
    };
    match nonos_filesystem::NONOS_FILESYSTEM.get_file_info(&entry.path) {
        Ok(info) => {
            let st = KernelStat {
                mode: 0,
                file_type: 1,
                size: info.size as u64,
                atime: info.modified,
                mtime: info.modified,
                ctime: info.created,
            };
            write_stat(statbuf, &st)
        }
        Err(_) => false,
    }
}

/// mkdir (syscall implementation)
pub fn mkdir_syscall(pathname: *const u8) -> Result<(), &'static str> {
    let path = cstr_to_string(pathname)?;
    crate::fs::nonos_vfs::get_vfs()
        .ok_or("VFS not initialized")?
        .mkdir_all(&path)
}

/// rename (syscall implementation)
pub fn rename_syscall(oldpath: *const u8, newpath: *const u8) -> Result<(), &'static str> {
    let old = cstr_to_string(oldpath)?;
    let new = cstr_to_string(newpath)?;
    crate::fs::nonos_vfs::get_vfs()
        .ok_or("VFS not initialized")?
        .rename(&old, &new)
}

/// Remove directory 
pub fn rmdir_syscall(pathname: *const u8) -> Result<(), &'static str> {
    if pathname.is_null() {
        return Err("Invalid path");
    }
    let path = cstr_to_string(pathname)?;
    crate::fs::nonos_vfs::get_vfs()
        .ok_or("VFS not initialized")?
        .rmdir(&path)
}

/// Unlink (syscall implementation)
pub fn unlink_syscall(pathname: *const u8) -> Result<(), &'static str> {
    if pathname.is_null() {
        return Err("Invalid path");
    }
    let path = cstr_to_string(pathname)?;
    crate::fs::nonos_vfs::get_vfs()
        .ok_or("VFS not initialized")?
        .unlink(&path)
}

/// Sync all filesystem buffers to disk (RAM-only: no-op)
pub fn sync_all() -> Result<(), &'static str> {
    Ok(())
}
