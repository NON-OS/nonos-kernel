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

pub const IOV_MAX: usize = 1024;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IoVec {
    pub iov_base: usize,
    pub iov_len: usize,
}

impl IoVec {
    pub const fn new(base: usize, len: usize) -> Self { Self { iov_base: base, iov_len: len } }
    pub const fn empty() -> Self { Self { iov_base: 0, iov_len: 0 } }
    pub fn is_empty(&self) -> bool { self.iov_len == 0 }
    pub fn end(&self) -> usize { self.iov_base.saturating_add(self.iov_len) }
}

pub fn validate_iovec(iov_ptr: usize, iov_cnt: usize) -> Result<&'static [IoVec], i32> {
    if iov_cnt == 0 || iov_cnt > IOV_MAX { return Err(-22); }
    if iov_ptr == 0 { return Err(-14); }
    let iovecs = unsafe { core::slice::from_raw_parts(iov_ptr as *const IoVec, iov_cnt) };
    for iov in iovecs {
        if iov.iov_len > 0 && iov.iov_base == 0 { return Err(-14); }
        if iov.iov_base.checked_add(iov.iov_len).is_none() { return Err(-14); }
    }
    Ok(iovecs)
}

pub fn total_iovec_len(iovecs: &[IoVec]) -> usize {
    iovecs.iter().map(|v| v.iov_len).sum()
}

pub fn count_nonempty(iovecs: &[IoVec]) -> usize {
    iovecs.iter().filter(|v| v.iov_len > 0).count()
}

pub fn validate_iovec_access(iovecs: &[IoVec], writable: bool) -> Result<(), i32> {
    for iov in iovecs {
        if iov.iov_len == 0 { continue; }
        let ptr = iov.iov_base as *const u8;
        if writable {
            let test_ptr = iov.iov_base as *mut u8;
            unsafe { core::ptr::read_volatile(test_ptr); }
        } else {
            unsafe { core::ptr::read_volatile(ptr); }
        }
    }
    Ok(())
}

pub fn copy_from_user_iovec(user_ptr: usize, count: usize) -> Result<alloc::vec::Vec<IoVec>, i32> {
    if count == 0 || count > IOV_MAX { return Err(-22); }
    if user_ptr == 0 { return Err(-14); }
    let mut result = alloc::vec::Vec::with_capacity(count);
    let src = user_ptr as *const IoVec;
    for i in 0..count {
        let iov = unsafe { core::ptr::read(src.add(i)) };
        result.push(iov);
    }
    Ok(result)
}

pub fn advance_iovec(iovecs: &[IoVec], offset: usize) -> (usize, usize) {
    let mut remaining = offset;
    for (idx, iov) in iovecs.iter().enumerate() {
        if remaining < iov.iov_len {
            return (idx, remaining);
        }
        remaining -= iov.iov_len;
    }
    (iovecs.len(), 0)
}
