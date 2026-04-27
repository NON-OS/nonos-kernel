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

use super::access::{check_process_access, get_target_cr3, is_same_address_space};
use super::copy::copy_from_remote;
use super::iovec::{validate_iovec, validate_iovec_access, IoVec};

pub fn sys_process_vm_readv(
    pid: i32,
    local_iov: usize,
    liovcnt: usize,
    remote_iov: usize,
    riovcnt: usize,
    _flags: u64,
) -> i64 {
    let target_pid = match check_process_access(pid) {
        Ok(p) => p,
        Err(e) => return e as i64,
    };
    let local = match validate_iovec(local_iov, liovcnt) {
        Ok(v) => v,
        Err(e) => return e as i64,
    };
    let remote = match validate_iovec(remote_iov, riovcnt) {
        Ok(v) => v,
        Err(e) => return e as i64,
    };
    if validate_iovec_access(&local, true).is_err() {
        return -14;
    }
    if is_same_address_space(target_pid) {
        return readv_same_space(&local, &remote);
    }
    let cr3 = match get_target_cr3(target_pid) {
        Some(c) => c,
        None => return -3,
    };
    readv_cross_space(cr3, &local, &remote)
}

fn readv_same_space(local: &[IoVec], remote: &[IoVec]) -> i64 {
    let mut total_read = 0usize;
    let mut local_idx = 0;
    let mut local_off = 0;
    for riov in remote {
        if riov.iov_len == 0 {
            continue;
        }
        let mut remote_addr = riov.iov_base;
        let mut remaining = riov.iov_len;
        while remaining > 0 && local_idx < local.len() {
            let liov = &local[local_idx];
            let local_avail = liov.iov_len - local_off;
            if local_avail == 0 {
                local_idx += 1;
                local_off = 0;
                continue;
            }
            let to_copy = remaining.min(local_avail);
            let local_addr = (liov.iov_base + local_off) as u64;
            let mut buf = alloc::vec![0u8; to_copy];
            if crate::usercopy::copy_from_user(remote_addr as u64, &mut buf).is_err() {
                return total_read as i64;
            }
            if crate::usercopy::copy_to_user(local_addr, &buf).is_err() {
                return total_read as i64;
            }
            total_read += to_copy;
            local_off += to_copy;
            remote_addr += to_copy;
            remaining -= to_copy;
        }
    }
    total_read as i64
}

fn readv_cross_space(cr3: u64, local: &[IoVec], remote: &[IoVec]) -> i64 {
    let mut total_read = 0usize;
    let mut local_idx = 0;
    let mut local_off = 0;
    for riov in remote {
        if riov.iov_len == 0 {
            continue;
        }
        let mut remote_addr = riov.iov_base;
        let mut remaining = riov.iov_len;
        while remaining > 0 && local_idx < local.len() {
            let liov = &local[local_idx];
            let local_avail = liov.iov_len - local_off;
            if local_avail == 0 {
                local_idx += 1;
                local_off = 0;
                continue;
            }
            let to_copy = remaining.min(local_avail);
            let local_addr = (liov.iov_base + local_off) as u64;
            let mut buf = alloc::vec![0u8; to_copy];
            match copy_from_remote(cr3, remote_addr, &mut buf) {
                Ok(n) => {
                    if crate::usercopy::copy_to_user(local_addr, &buf[..n]).is_err() {
                        return total_read as i64;
                    }
                    total_read += n;
                    local_off += n;
                    remote_addr += n;
                    remaining -= n;
                }
                Err(_) => return total_read as i64,
            }
        }
    }
    total_read as i64
}
