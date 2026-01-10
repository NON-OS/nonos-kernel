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

use crate::crypto::symmetric::aes::Aes256;

use super::ghash::{GhashKey, GhashState, gf128_xor, u128_to_block};

#[inline]
pub fn inc32(counter: &mut [u8; 16]) {
    let ctr = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]);
    let incremented = ctr.wrapping_add(1);
    counter[12..16].copy_from_slice(&incremented.to_be_bytes());
}

#[inline]
pub fn derive_j0(nonce: &[u8; 12]) -> [u8; 16] {
    let mut j0 = [0u8; 16];
    j0[0..12].copy_from_slice(nonce);
    j0[15] = 1;
    j0
}

pub fn aes_ctr_gcm(aes: &Aes256, j0: &[u8; 16], data: &mut [u8]) {
    if data.is_empty() {
        return;
    }

    let mut counter = *j0;
    inc32(&mut counter);

    let mut offset = 0;
    while offset < data.len() {
        let keystream = aes.encrypt_block(&counter);
        let block_len = (data.len() - offset).min(16);

        for i in 0..block_len {
            data[offset + i] ^= keystream[i];
        }

        offset += block_len;
        inc32(&mut counter);
    }
}

pub fn compute_tag(aes: &Aes256, ghash_key: &GhashKey, j0: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut ghash = GhashState::new(ghash_key.clone());
    ghash.update_aad(aad);
    ghash.update_ct(ciphertext);
    let s = ghash.finalize();
    let ek_j0 = aes.encrypt_block(j0);
    let s_block = u128_to_block(s);
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = ek_j0[i] ^ s_block[i];
    }

    tag
}
