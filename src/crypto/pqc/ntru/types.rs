// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use alloc::vec::Vec;
#[derive(Clone)]
pub struct NtruPublicKey {
    pub h: Vec<i16>,
}

#[derive(Clone)]
pub struct NtruSecretKey {
    pub f: Vec<i16>,
    pub fp: Vec<i16>,
    pub pk: NtruPublicKey,
}

impl Drop for NtruSecretKey {
    fn drop(&mut self) {
        // SAFETY: Volatile writes ensure secret data is zeroized and not optimized away.
        for coeff in &mut self.f {
            unsafe { core::ptr::write_volatile(coeff, 0) };
        }
        for coeff in &mut self.fp {
            unsafe { core::ptr::write_volatile(coeff, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Clone)]
pub struct NtruKeyPair {
    pub public_key: NtruPublicKey,
    pub secret_key: NtruSecretKey,
}

#[derive(Clone)]
pub struct NtruCiphertext {
    pub c: Vec<i16>,
}
