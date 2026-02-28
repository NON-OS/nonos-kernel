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
use super::core::{hmac_sha256, hmac_sha512};

pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    let h_len = 32;
    let l = (dk_len + h_len - 1) / h_len;

    let mut derived_key = Vec::with_capacity(dk_len);

    for i in 1..=l {
        let mut prf_input = Vec::with_capacity(salt.len() + 4);
        prf_input.extend_from_slice(salt);
        prf_input.extend_from_slice(&(i as u32).to_be_bytes());

        let mut u = hmac_sha256(password, &prf_input);
        let mut f = u.clone();

        for _ in 1..iterations {
            u = hmac_sha256(password, &u);

            for j in 0..h_len {
                f[j] ^= u[j];
            }
        }

        derived_key.extend_from_slice(&f);
    }

    derived_key.truncate(dk_len);
    derived_key
}

pub fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    let h_len = 64;
    let l = (dk_len + h_len - 1) / h_len;

    let mut derived_key = Vec::with_capacity(dk_len);

    for i in 1..=l {
        let mut prf_input = Vec::with_capacity(salt.len() + 4);
        prf_input.extend_from_slice(salt);
        prf_input.extend_from_slice(&(i as u32).to_be_bytes());

        let mut u = hmac_sha512(password, &prf_input);
        let mut f = u;

        for _ in 1..iterations {
            u = hmac_sha512(password, &u);

            for j in 0..h_len {
                f[j] ^= u[j];
            }
        }

        derived_key.extend_from_slice(&f);

        for b in f.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
    }

    derived_key.truncate(dk_len);
    derived_key
}
