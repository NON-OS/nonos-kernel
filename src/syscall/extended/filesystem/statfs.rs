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

use super::super::errno;
use super::helpers::{read_user_string, resolve_path_at};
use crate::syscall::SyscallResult;
use crate::usercopy::copy_to_user;
use alloc::string::String;

pub fn handle_faccessat(dirfd: i32, pathname: u64, mode: i32) -> SyscallResult {
    if pathname == 0 {
        return errno(14);
    }

    let path = match read_user_string(pathname, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    let full_path = resolve_path_at(dirfd, &path);
    let _ = mode;

    if let Some(vfs) = crate::fs::nonos_vfs::get_vfs() {
        if vfs.exists(&full_path) {
            return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
        }
    }

    errno(2)
}

pub fn handle_statfs(path: u64, buf: u64) -> SyscallResult {
    if path == 0 || buf == 0 {
        return errno(14);
    }

    let path_str = match read_user_string(path, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    if !crate::fs::nonos_vfs::get_vfs().map(|v| v.exists(&path_str)).unwrap_or(false) {
        return errno(2);
    }

    let statfs_buf = build_statfs_buf();
    if copy_to_user(buf, &statfs_buf).is_err() {
        return errno(14);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_fstatfs(fd: i32, buf: u64) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    if buf == 0 {
        return errno(14);
    }

    let statfs_buf = build_statfs_buf();
    if copy_to_user(buf, &statfs_buf).is_err() {
        return errno(14);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

fn build_statfs_buf() -> [u8; 120] {
    let mut buf = [0u8; 120];
    buf[0..8].copy_from_slice(&0x4e4f4e4f53u64.to_ne_bytes());
    buf[8..16].copy_from_slice(&4096u64.to_ne_bytes());
    buf[16..24].copy_from_slice(&(1024u64 * 1024).to_ne_bytes());
    buf[24..32].copy_from_slice(&(512u64 * 1024).to_ne_bytes());
    buf[32..40].copy_from_slice(&(512u64 * 1024).to_ne_bytes());
    buf[40..48].copy_from_slice(&1000000u64.to_ne_bytes());
    buf[48..56].copy_from_slice(&999000u64.to_ne_bytes());
    buf[88..96].copy_from_slice(&255u64.to_ne_bytes());
    buf
}

pub fn handle_statx(
    dirfd: i32,
    pathname: u64,
    flags: i32,
    mask: u32,
    statxbuf: u64,
) -> SyscallResult {
    if statxbuf == 0 {
        return errno(14);
    }

    let path = if pathname != 0 {
        match read_user_string(pathname, 4096) {
            Ok(s) => s,
            Err(_) => return errno(14),
        }
    } else {
        String::new()
    };

    let full_path = if path.is_empty() && (flags & 0x1000) != 0 {
        match crate::fs::fd::fd_get_path(dirfd) {
            Ok(p) => p,
            Err(_) => return errno(9),
        }
    } else {
        resolve_path_at(dirfd, &path)
    };

    let vfs = match crate::fs::nonos_vfs::get_vfs() {
        Some(v) => v,
        None => return errno(5),
    };

    let metadata = match vfs.stat(&full_path) {
        Ok(m) => m,
        Err(_) => return errno(2),
    };

    let _ = mask;
    let statx_buf = build_statx_buf(&metadata);

    if copy_to_user(statxbuf, &statx_buf).is_err() {
        return errno(14);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

fn build_statx_buf(metadata: &crate::fs::FileMetadata) -> [u8; 256] {
    let mut buf = [0u8; 256];
    buf[0..4].copy_from_slice(&0x7FFu32.to_ne_bytes());
    buf[4..8].copy_from_slice(&4096u32.to_ne_bytes());
    buf[16..20].copy_from_slice(&1u32.to_ne_bytes());
    buf[28..30].copy_from_slice(&((metadata.mode & 0xFFFF) as u16).to_ne_bytes());
    buf[32..40].copy_from_slice(&metadata.inode.to_ne_bytes());
    buf[40..48].copy_from_slice(&metadata.size.to_ne_bytes());
    buf[48..56].copy_from_slice(&((metadata.size + 511) / 512).to_ne_bytes());
    buf
}
