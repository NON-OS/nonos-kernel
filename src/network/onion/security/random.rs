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


use crate::crypto::entropy;

pub struct SecureRandom;

impl SecureRandom {
    pub fn generate_nonce() -> [u8; 32] {
        let mut nonce = [0u8; 32];
        entropy::fill_random(&mut nonce);
        nonce
    }

    pub fn generate_session_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        entropy::fill_random(&mut key);
        key
    }

    pub fn generate_circuit_id() -> u32 {
        loop {
            let id = entropy::rand_u32();
            if id != 0 {
                return id;
            }
        }
    }

    pub fn timing_jitter_ms() -> u32 {
        entropy::rand_u32() % 50
    }
}
