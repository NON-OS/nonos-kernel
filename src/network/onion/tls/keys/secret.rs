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

pub(crate) struct Secret {
    pub secret: [u8; 48],
    pub len: usize,
}

impl Secret {
    pub(crate) fn new(len: usize) -> Self {
        Self { secret: [0u8; 48], len }
    }
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.secret[..self.len]
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        for byte in self.secret.iter_mut() {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
