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

use alloc::vec::Vec;
use super::erase::{sanitize, sanitize_slice};

pub struct SensitiveData<T> {
    data: T,
    sanitize_on_drop: bool,
}

impl<T> SensitiveData<T> {
    pub fn new(data: T) -> Self {
        Self {
            data,
            sanitize_on_drop: true,
        }
    }

    pub fn new_no_sanitize(data: T) -> Self {
        Self {
            data,
            sanitize_on_drop: false,
        }
    }

    pub fn as_ref(&self) -> &T {
        &self.data
    }

    pub fn as_mut(&mut self) -> &mut T {
        &mut self.data
    }

    pub fn into_inner(mut self) -> T {
        self.sanitize_on_drop = false;
        // SAFETY: zeroed is safe for any type T we're replacing
        core::mem::replace(&mut self.data, unsafe { core::mem::zeroed() })
    }
}

impl<T> Drop for SensitiveData<T> {
    fn drop(&mut self) {
        if self.sanitize_on_drop {
            let ptr = &mut self.data as *mut T as *mut u8;
            let size = core::mem::size_of::<T>();
            sanitize(ptr, size);
        }
    }
}

pub struct SecureString {
    data: Vec<u8>,
}

impl SecureString {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            data: bytes.to_vec(),
        }
    }

    pub fn push(&mut self, byte: u8) {
        self.data.push(byte);
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn clear(&mut self) {
        sanitize_slice(&mut self.data);
        self.data.clear();
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        if !self.data.is_empty() {
            sanitize_slice(&mut self.data);
        }
    }
}

impl Default for SecureString {
    fn default() -> Self {
        Self::new()
    }
}
