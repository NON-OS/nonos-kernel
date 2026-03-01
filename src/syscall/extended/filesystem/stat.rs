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

use crate::syscall::SyscallResult;
use super::super::errno;
use super::helpers::read_user_string;

pub fn handle_access(pathname: u64, mode: u64) -> SyscallResult {
    const F_OK: u64 = 0;

    if pathname == 0 {
        return errno(14);
    }

    let path = match read_user_string(pathname, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    let exists = if let Some(vfs) = crate::fs::nonos_vfs::get_vfs() {
        vfs.exists(&path)
    } else {
        false
    };

    if !exists && (mode & F_OK) != 0 {
        return errno(2);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_readlink(pathname: u64, buf: u64, bufsiz: u64) -> SyscallResult {
    if pathname == 0 || buf == 0 || bufsiz == 0 {
        return errno(22);
    }

    let path = match read_user_string(pathname, 4096) {
        Ok(p) => p,
        Err(_) => return errno(14),
    };

    let target = match crate::fs::readlink(&path) {
        Ok(t) => t,
        Err(e) => {
            if e == "Not a symbolic link" {
                return errno(22);
            }
            return errno(2);
        }
    };

    let target_bytes = target.as_bytes();
    let copy_len = core::cmp::min(target_bytes.len(), bufsiz as usize);

    // SAFETY: buf is user-provided pointer for readlink output.
    unsafe {
        core::ptr::copy_nonoverlapping(
            target_bytes.as_ptr(),
            buf as *mut u8,
            copy_len,
        );
    }

    SyscallResult { value: copy_len as i64, capability_consumed: false, audit_required: false }
}

pub fn handle_lstat(pathname: u64, statbuf: u64) -> SyscallResult {
    if pathname == 0 || statbuf == 0 {
        return errno(22);
    }

    let path = match read_user_string(pathname, 4096) {
        Ok(p) => p,
        Err(_) => return errno(14),
    };

    let vfs = match crate::fs::nonos_vfs::get_vfs() {
        Some(v) => v,
        None => return errno(5),
    };

    let metadata = match vfs.stat(&path) {
        Ok(m) => m,
        Err(_) => return errno(2),
    };

    // SAFETY: statbuf is user-provided pointer for stat output.
    unsafe {
        let buf = statbuf as *mut u8;
        core::ptr::write_bytes(buf, 0, 128);

        core::ptr::write((buf.add(0)) as *mut u64, 1);
        core::ptr::write((buf.add(8)) as *mut u64, metadata.inode);
        core::ptr::write((buf.add(16)) as *mut u64, 1);
        core::ptr::write((buf.add(24)) as *mut u32, metadata.mode);
        core::ptr::write((buf.add(28)) as *mut u32, 0);
        core::ptr::write((buf.add(32)) as *mut u32, 0);
        core::ptr::write((buf.add(48)) as *mut i64, metadata.size as i64);
        core::ptr::write((buf.add(56)) as *mut i64, 4096);
        core::ptr::write((buf.add(64)) as *mut i64, (metadata.size + 511) as i64 / 512);
        core::ptr::write((buf.add(72)) as *mut i64, metadata.atime as i64);
        core::ptr::write((buf.add(88)) as *mut i64, metadata.mtime as i64);
        core::ptr::write((buf.add(104)) as *mut i64, metadata.ctime as i64);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}
