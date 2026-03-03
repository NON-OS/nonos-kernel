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
use super::constants::{KEY_LEN, IV_LEN, DIGEST_LEN};
use super::provider::provider;
use super::handshake::HopCrypto;

#[derive(Debug, Clone)]
pub struct LayerKeys {
    pub forward_key: [u8; KEY_LEN],
    pub backward_key: [u8; KEY_LEN],
    pub forward_iv: [u8; IV_LEN],
    pub backward_iv: [u8; IV_LEN],
    pub forward_digest: [u8; DIGEST_LEN],
    pub backward_digest: [u8; DIGEST_LEN],
    fwd_ctr_blocks: u128,
    bwd_ctr_blocks: u128,
}

impl LayerKeys {
    pub fn new(
        forward_key: [u8; KEY_LEN],
        backward_key: [u8; KEY_LEN],
        forward_iv: [u8; IV_LEN],
        backward_iv: [u8; IV_LEN],
        forward_digest: [u8; DIGEST_LEN],
        backward_digest: [u8; DIGEST_LEN],
    ) -> Self {
        Self {
            forward_key,
            backward_key,
            forward_iv,
            backward_iv,
            forward_digest,
            backward_digest,
            fwd_ctr_blocks: 0,
            bwd_ctr_blocks: 0,
        }
    }

    pub fn encrypt_forward(&mut self, data: &[u8]) -> Result<Vec<u8>, OnionError> {
        let mut out = data.to_vec();
        if !out.is_empty() {
            provider().aes128_ctr_apply(
                &self.forward_key,
                &self.forward_iv,
                self.fwd_ctr_blocks,
                &mut out,
            );
            self.bump_forward(&out);
        }
        Ok(out)
    }

    pub fn decrypt_backward(&mut self, data: &[u8]) -> Result<Vec<u8>, OnionError> {
        let mut out = data.to_vec();
        if !out.is_empty() {
            provider().aes128_ctr_apply(
                &self.backward_key,
                &self.backward_iv,
                self.bwd_ctr_blocks,
                &mut out,
            );
            self.bump_backward(&out);
        }
        Ok(out)
    }

    #[inline]
    fn bump_forward(&mut self, ciphertext: &[u8]) {
        let mut h = [0u8; 32];
        provider().blake3(ciphertext, &mut h);
        self.forward_digest.copy_from_slice(&h[..DIGEST_LEN]);
        self.fwd_ctr_blocks = self
            .fwd_ctr_blocks
            .saturating_add(((ciphertext.len() + 15) / 16) as u128);
    }

    #[inline]
    fn bump_backward(&mut self, plaintext: &[u8]) {
        let mut h = [0u8; 32];
        provider().blake3(plaintext, &mut h);
        self.backward_digest.copy_from_slice(&h[..DIGEST_LEN]);
        self.bwd_ctr_blocks = self
            .bwd_ctr_blocks
            .saturating_add(((plaintext.len() + 15) / 16) as u128);
    }

    pub fn from_hop_crypto(hc: &HopCrypto) -> Self {
        let mut lk = LayerKeys {
            forward_key: [0u8; KEY_LEN],
            backward_key: [0u8; KEY_LEN],
            forward_iv: [0u8; IV_LEN],
            backward_iv: [0u8; IV_LEN],
            forward_digest: [0u8; DIGEST_LEN],
            backward_digest: [0u8; DIGEST_LEN],
            fwd_ctr_blocks: 0,
            bwd_ctr_blocks: 0,
        };
        lk.forward_key.copy_from_slice(&hc.forward_key[..KEY_LEN]);
        lk.backward_key.copy_from_slice(&hc.backward_key[..KEY_LEN]);
        lk.forward_iv.copy_from_slice(&hc.forward_iv[..IV_LEN]);
        lk.backward_iv.copy_from_slice(&hc.backward_iv[..IV_LEN]);
        lk
    }
}
