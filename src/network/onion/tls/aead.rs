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
use crate::network::onion::OnionError;
use super::types::{CipherSuite, ContentType, TLS_1_2};
use super::keys::{expand_label_len, Secret};
use super::crypto_provider::crypto;

pub(super) struct AeadState {
    key: Vec<u8>,
    iv: [u8; 12],
    seq: u64,
}

impl Drop for AeadState {
    fn drop(&mut self) {
        for byte in self.key.iter_mut() {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        for byte in self.iv.iter_mut() {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl AeadState {
    pub(super) fn empty() -> Self {
        Self {
            key: Vec::new(),
            iv: [0u8; 12],
            seq: 0,
        }
    }

    pub(super) fn from_secret(sec: &Secret, suite: CipherSuite) -> Result<Self, OnionError> {
        use crate::sys::serial;

        let key_len = match suite {
            CipherSuite::TlsAes128GcmSha256 => 16,
            CipherSuite::TlsChacha20Poly1305Sha256 => 32,
        };
        let mut iv = [0u8; 12];
        expand_label_len(&sec.secret, b"iv", &[], &mut iv);
        let mut key = vec![0u8; key_len];
        expand_label_len(&sec.secret, b"key", &[], &mut key);

        serial::print(b"[AEAD] from_secret: secret=");
        for i in 0..8.min(sec.secret.len()) {
            serial::print_hex(sec.secret[i] as u64);
            serial::print(b" ");
        }
        serial::println(b"");

        serial::print(b"[AEAD] from_secret: key=");
        for i in 0..8.min(key.len()) {
            serial::print_hex(key[i] as u64);
            serial::print(b" ");
        }
        serial::println(b"");

        serial::print(b"[AEAD] from_secret: iv=");
        for i in 0..12 {
            serial::print_hex(iv[i] as u64);
            serial::print(b" ");
        }
        serial::println(b"");

        Ok(Self { key, iv, seq: 0 })
    }

    #[inline]
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq_bytes = self.seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        nonce
    }

    pub(super) fn seal(&mut self, suite: CipherSuite, inner_type: ContentType, plaintext: &[u8]) -> Result<Vec<u8>, OnionError> {
        use crate::sys::serial;

        let mut inner = Vec::with_capacity(plaintext.len() + 1);
        inner.extend_from_slice(plaintext);
        inner.push(inner_type as u8);

        let total_len = (inner.len() + 16) as u16;
        let mut header = [0u8; 5];
        header[0] = ContentType::ApplicationData as u8;
        header[1..3].copy_from_slice(&TLS_1_2.to_be_bytes());
        header[3..5].copy_from_slice(&total_len.to_be_bytes());

        let nonce = self.nonce();

        serial::print(b"[AEAD] seal suite=");
        serial::print_dec(match suite {
            CipherSuite::TlsAes128GcmSha256 => 0x1301,
            CipherSuite::TlsChacha20Poly1305Sha256 => 0x1303,
        });
        serial::print(b" seq=");
        serial::print_dec(self.seq);
        serial::print(b" inner_type=");
        serial::print_hex(inner_type as u64);
        serial::print(b" inner_len=");
        serial::print_dec(inner.len() as u64);
        serial::println(b"");

        serial::print(b"[AEAD] key=");
        for i in 0..self.key.len().min(8) {
            serial::print_hex(self.key[i] as u64);
            serial::print(b" ");
        }
        serial::println(b"");

        serial::print(b"[AEAD] iv=");
        for i in 0..12 {
            serial::print_hex(self.iv[i] as u64);
            serial::print(b" ");
        }
        serial::println(b"");

        serial::print(b"[AEAD] nonce=");
        for i in 0..12 {
            serial::print_hex(nonce[i] as u64);
            serial::print(b" ");
        }
        serial::println(b"");

        serial::print(b"[AEAD] aad=");
        for i in 0..5 {
            serial::print_hex(header[i] as u64);
            serial::print(b" ");
        }
        serial::println(b"");

        let ciphertext = crypto().aead_seal(suite, &self.key, &nonce, &header, &inner)?;

        serial::print(b"[AEAD] ct_len=");
        serial::print_dec(ciphertext.len() as u64);
        serial::print(b" tag=");
        // Print last 16 bytes (the auth tag)
        let tag_start = if ciphertext.len() >= 16 { ciphertext.len() - 16 } else { 0 };
        for i in tag_start..ciphertext.len().min(tag_start + 4) {
            serial::print_hex(ciphertext[i] as u64);
            serial::print(b" ");
        }
        serial::println(b"");

        // For application data, print the plaintext HTTP request first bytes
        if inner_type == ContentType::ApplicationData && plaintext.len() > 0 {
            serial::print(b"[AEAD] plaintext=");
            for i in 0..20.min(plaintext.len()) {
                serial::print_hex(plaintext[i] as u64);
                serial::print(b" ");
            }
            serial::println(b"...");
        }

        self.seq = self.seq.wrapping_add(1);
        Ok(ciphertext)
    }

    pub(super) fn open(&mut self, suite: CipherSuite, outer_type: ContentType, ciphertext: &[u8]) -> Result<Vec<u8>, OnionError> {
        let mut header = [0u8; 5];
        header[0] = outer_type as u8;
        header[1..3].copy_from_slice(&TLS_1_2.to_be_bytes());
        let total_len = ciphertext.len() as u16;
        header[3..5].copy_from_slice(&total_len.to_be_bytes());

        let nonce = self.nonce();
        let pt = crypto().aead_open(suite, &self.key, &nonce, &header, ciphertext)?;
        self.seq = self.seq.wrapping_add(1);
        Ok(pt)
    }
}
