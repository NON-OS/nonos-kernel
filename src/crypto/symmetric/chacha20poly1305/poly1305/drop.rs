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

use super::super::chacha20::secure_zero_bytes;
use super::types::Poly1305;

impl Drop for Poly1305 {
    fn drop(&mut self) {
        // SAFETY: Volatile writes ensure zeroing of sensitive cryptographic state.
        unsafe {
            core::ptr::write_volatile(&mut self.h0, 0);
            core::ptr::write_volatile(&mut self.h1, 0);
            core::ptr::write_volatile(&mut self.h2, 0);
            core::ptr::write_volatile(&mut self.h3, 0);
            core::ptr::write_volatile(&mut self.h4, 0);
            core::ptr::write_volatile(&mut self.r0, 0);
            core::ptr::write_volatile(&mut self.r1, 0);
            core::ptr::write_volatile(&mut self.r2, 0);
            core::ptr::write_volatile(&mut self.r3, 0);
            core::ptr::write_volatile(&mut self.r4, 0);
            core::ptr::write_volatile(&mut self.s1, 0);
            core::ptr::write_volatile(&mut self.s2, 0);
            core::ptr::write_volatile(&mut self.s3, 0);
            core::ptr::write_volatile(&mut self.s4, 0);
            core::ptr::write_volatile(&mut self.buffer_len, 0);
        }
        secure_zero_bytes(&mut self.s);
        secure_zero_bytes(&mut self.buffer);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
