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

use super::super::errno;
use super::helpers::read_user_string;
use crate::syscall::SyscallResult;
use crate::usercopy::copy_to_user;

pub fn handle_access(pathname: u64, mode: u64) -> SyscallResult {
    const F_OK: u64 = 0;

    if pathname == 0 {
        return errno(14);
    }

    let path = match read_user_string(pathname, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    let exists =
        if let Some(vfs) = crate::fs::nonos_vfs::get_vfs() { vfs.exists(&path) } else { false };

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

    if copy_to_user(buf, &target_bytes[..copy_len]).is_err() {
        return errno(14);
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

    let mut stat_buf = [0u8; 128];
    let dev: u64 = 1;
    let nlink: u64 = 1;
    let blksize: i64 = 4096;
    let blocks: i64 = (metadata.size + 511) as i64 / 512;

    stat_buf[0..8].copy_from_slice(&dev.to_ne_bytes());
    stat_buf[8..16].copy_from_slice(&metadata.inode.to_ne_bytes());
    stat_buf[16..24].copy_from_slice(&nlink.to_ne_bytes());
    stat_buf[24..28].copy_from_slice(&metadata.mode.to_ne_bytes());
    stat_buf[48..56].copy_from_slice(&(metadata.size as i64).to_ne_bytes());
    stat_buf[56..64].copy_from_slice(&blksize.to_ne_bytes());
    stat_buf[64..72].copy_from_slice(&blocks.to_ne_bytes());
    stat_buf[72..80].copy_from_slice(&(metadata.atime as i64).to_ne_bytes());
    stat_buf[88..96].copy_from_slice(&(metadata.mtime as i64).to_ne_bytes());
    stat_buf[104..112].copy_from_slice(&(metadata.ctime as i64).to_ne_bytes());

    if copy_to_user(statbuf, &stat_buf).is_err() {
        return errno(14);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}
