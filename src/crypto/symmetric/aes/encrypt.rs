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

use crate::crypto::constant_time::{secure_zero, compiler_fence};
use super::core::{add_round_key, sub_bytes, shift_rows, mix_columns, inv_shift_rows, inv_sub_bytes, inv_mix_columns};
use super::key_schedule::expand_key_128;
use super::modes::increment_be128;
use super::AES128_ROUNDS;

#[derive(Clone)]
pub struct Aes128 {
    round_keys: [[u8; 16]; 11],
}

impl Drop for Aes128 {
    fn drop(&mut self) {
        for rk in &mut self.round_keys {
            secure_zero(rk);
        }
        compiler_fence();
    }
}

impl Aes128 {
    pub fn new(key: &[u8; 16]) -> Self {
        let mut aes = Self { round_keys: [[0u8; 16]; 11] };
        expand_key_128(key, &mut aes.round_keys);
        aes
    }

    pub fn encrypt_block(&self, plaintext: &[u8; 16]) -> [u8; 16] {
        let mut state = *plaintext;

        add_round_key(&mut state, &self.round_keys[0]);

        for round in 1..AES128_ROUNDS {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, &self.round_keys[round]);
        }

        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &self.round_keys[AES128_ROUNDS]);

        state
    }

    pub fn decrypt_block(&self, ciphertext: &[u8; 16]) -> [u8; 16] {
        let mut state = *ciphertext;

        add_round_key(&mut state, &self.round_keys[AES128_ROUNDS]);

        for round in (1..AES128_ROUNDS).rev() {
            inv_shift_rows(&mut state);
            inv_sub_bytes(&mut state);
            add_round_key(&mut state, &self.round_keys[round]);
            inv_mix_columns(&mut state);
        }

        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, &self.round_keys[0]);

        state
    }

    pub fn ctr_apply(&self, nonce_counter: &mut [u8; 16], data: &mut [u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let mut keystream = self.encrypt_block(nonce_counter);
            let chunk = (data.len() - offset).min(16);
            for i in 0..chunk {
                data[offset + i] ^= keystream[i];
            }
            secure_zero(&mut keystream);
            offset += chunk;
            increment_be128(nonce_counter);
        }
        compiler_fence();
    }
}
