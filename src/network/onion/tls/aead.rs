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
use super::keys::{expand_label, Secret};
use super::crypto_provider::crypto;

pub(super) struct AeadState {
    key: Vec<u8>,
    iv: [u8; 12],
    seq: u64,
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
        let key_len = match suite {
            CipherSuite::TlsAes128GcmSha256 => 16,
            CipherSuite::TlsChacha20Poly1305Sha256 => 32,
        };
        let iv_full = expand_label(&sec.secret, b"iv", &[]);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_full[..12]);
        let key = expand_label(&sec.secret, b"key", &[])[..key_len].to_vec();
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
        let mut inner = Vec::with_capacity(plaintext.len() + 1);
        inner.extend_from_slice(plaintext);
        inner.push(inner_type as u8);

        let total_len = (inner.len() + 16) as u16;
        let mut header = [0u8; 5];
        header[0] = ContentType::ApplicationData as u8;
        header[1..3].copy_from_slice(&TLS_1_2.to_be_bytes());
        header[3..5].copy_from_slice(&total_len.to_be_bytes());

        let nonce = self.nonce();
        let ciphertext = crypto().aead_seal(suite, &self.key, &nonce, &header, &inner)?;
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
        let (&last, data) = pt.split_last().ok_or(OnionError::CryptoError)?;
        if last != ContentType::Handshake as u8 && last != ContentType::ApplicationData as u8 {
            return Err(OnionError::CryptoError);
        }
        self.seq = self.seq.wrapping_add(1);
        Ok(data.to_vec())
    }
}
