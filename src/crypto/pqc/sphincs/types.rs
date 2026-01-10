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

use super::SPHINCS_N;

#[derive(Clone)]
pub struct SphincsPublicKey {
    pub seed: [u8; SPHINCS_N],
    pub root: [u8; SPHINCS_N],
}

#[derive(Clone)]
pub struct SphincsSecretKey {
    pub sk_seed: [u8; SPHINCS_N],
    pub sk_prf: [u8; SPHINCS_N],
    pub pk_seed: [u8; SPHINCS_N],
    pub pk_root: [u8; SPHINCS_N],
}

impl Drop for SphincsSecretKey {
    fn drop(&mut self) {
        // SAFETY: Volatile writes prevent compiler from optimizing away the zeroing.
        // This ensures secret key material is securely erased from memory.
        for b in &mut self.sk_seed {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        for b in &mut self.sk_prf {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        for b in &mut self.pk_seed {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        for b in &mut self.pk_root {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Clone)]
pub struct SphincsKeyPair {
    pub public_key: SphincsPublicKey,
    pub secret_key: SphincsSecretKey,
}

pub struct SphincsSignature {
    pub bytes: Vec<u8>,
}
