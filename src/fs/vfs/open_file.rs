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

use alloc::string::String;
use core::sync::atomic::{Ordering, compiler_fence};

use super::types::OpenFlags;

#[inline]
pub fn secure_zeroize(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[inline]
pub fn secure_zeroize_string(s: &mut String) {
    // SAFETY: We're zeroing the string's buffer before clearing it
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
    pub fn secure_clear(&mut self) {
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
