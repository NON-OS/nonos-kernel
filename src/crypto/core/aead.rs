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

use crate::crypto::symmetric::{chacha20poly1305, aes_gcm};
use crate::crypto::CryptoError;

pub type CryptoResult<T> = core::result::Result<T, CryptoError>;

pub trait Aead {
    fn seal(&self, nonce96: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>>;
    fn open(&self, nonce96: &[u8; 12], aad: &[u8], ciphertext_and_tag: &[u8]) -> CryptoResult<Vec<u8>>;
    fn key_len() -> usize { 32 }
    fn nonce_len() -> usize { 12 }
    fn tag_len() -> usize { 16 }
}

pub struct Chacha20Poly1305Aead {
    key: [u8; 32],
}

impl Chacha20Poly1305Aead {
    pub fn new(key: &[u8; 32]) -> Self { Self { key: *key } }
}

impl Drop for Chacha20Poly1305Aead {
    fn drop(&mut self) {
        // SECURITY: Securely zeroize key material on drop
        for byte in self.key.iter_mut() {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Aead for Chacha20Poly1305Aead {
    fn seal(&self, nonce96: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        chacha20poly1305::aead_encrypt(&self.key, nonce96, aad, plaintext)
            .map_err(|_| CryptoError::SigError)
    }
    fn open(&self, nonce96: &[u8; 12], aad: &[u8], ct_and_tag: &[u8]) -> CryptoResult<Vec<u8>> {
        chacha20poly1305::aead_decrypt(&self.key, nonce96, aad, ct_and_tag)
            .map_err(|_| CryptoError::AeadTagMismatch)
    }
}

pub struct Aes256GcmAead {
    key: [u8; 32],
}

impl Aes256GcmAead {
    pub fn new(key: &[u8; 32]) -> Self { Self { key: *key } }
}

impl Drop for Aes256GcmAead {
    fn drop(&mut self) {
        // SECURITY: Securely zeroize key material on drop
        for byte in self.key.iter_mut() {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Aead for Aes256GcmAead {
    fn seal(&self, nonce96: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        aes_gcm::aes256_gcm_encrypt(&self.key, nonce96, aad, plaintext)
            .map_err(|_| CryptoError::SigError)
    }
    fn open(&self, nonce96: &[u8; 12], aad: &[u8], ct_and_tag: &[u8]) -> CryptoResult<Vec<u8>> {
        aes_gcm::aes256_gcm_decrypt(&self.key, nonce96, aad, ct_and_tag)
            .map_err(|_| CryptoError::AeadTagMismatch)
    }
}

pub fn aead_wrap<A: Aead>(aead: &A, nonce96: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut out = Vec::with_capacity(12 + plaintext.len() + 16);
    out.extend_from_slice(nonce96);
    let ct = aead.seal(nonce96, aad, plaintext)?;
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn aead_unwrap<A: Aead>(aead: &A, aad: &[u8], wrapped: &[u8]) -> CryptoResult<Vec<u8>> {
    if wrapped.len() < 12 + 16 {
        return Err(CryptoError::InvalidLength);
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&wrapped[..12]);
    let ct_and_tag = &wrapped[12..];
    aead.open(&nonce, aad, ct_and_tag)
}
