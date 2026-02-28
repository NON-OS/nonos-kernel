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

use alloc::vec::Vec;

#[derive(Clone)]
pub struct McEliecePublicKey {
    pub t_matrix: Vec<u8>,
}

#[derive(Clone)]
pub struct McElieceSecretKey {
    pub goppa_poly: Vec<u16>,
    pub support: Vec<u16>,
    pub permutation: Vec<u16>,
    pub pk: McEliecePublicKey,
}

impl Drop for McElieceSecretKey {
    fn drop(&mut self) {
        for coeff in &mut self.goppa_poly {
            // SAFETY: Volatile write ensures the compiler doesn't optimize away the zeroing.
            unsafe { core::ptr::write_volatile(coeff, 0) };
        }
        for elem in &mut self.support {
            // SAFETY: Volatile write ensures the compiler doesn't optimize away the zeroing.
            unsafe { core::ptr::write_volatile(elem, 0) };
        }
        for p in &mut self.permutation {
            // SAFETY: Volatile write ensures the compiler doesn't optimize away the zeroing.
            unsafe { core::ptr::write_volatile(p, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Clone)]
pub struct McElieceKeyPair {
    pub public_key: McEliecePublicKey,
    pub secret_key: McElieceSecretKey,
}

#[derive(Clone)]
pub struct McElieceCiphertext {
    pub c: Vec<u8>,
}
