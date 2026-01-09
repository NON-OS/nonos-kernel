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
use alloc::vec;
use alloc::vec::Vec;
use super::gf::GF2m;
use super::goppa::{poly_eval, berlekamp_massey, chien_search};
use super::{
    MCELIECE_N, MCELIECE_T, MCELIECE_SHARED_SECRET_BYTES,
    McElieceSecretKey, McElieceCiphertext, hash_error,
};

fn compute_syndrome_poly(ct: &[u8], goppa: &[u16], support: &[u16]) -> Vec<u16> {
    let mut syndrome = vec![0u16; MCELIECE_T];
    for i in 0..MCELIECE_N {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        if byte_idx >= ct.len() {
            continue;
        }
        if (ct[byte_idx] >> bit_idx) & 1 == 0 {
            continue;
        }

        let alpha = support[i];
        let g_alpha = poly_eval(goppa, alpha);
        if g_alpha == 0 {
            continue;
        }
        let g_alpha_inv = GF2m::inv(g_alpha);
        let mut power = g_alpha_inv;
        for j in 0..MCELIECE_T {
            syndrome[j] = GF2m::add(syndrome[j], power);
            power = GF2m::mul(power, alpha);
        }
    }

    syndrome
}

pub fn mceliece_decaps(ct: &McElieceCiphertext, sk: &McElieceSecretKey) -> Result<[u8; MCELIECE_SHARED_SECRET_BYTES], &'static str> {
    let syndrome = compute_syndrome_poly(&ct.c, &sk.goppa_poly, &sk.support);
    if syndrome.iter().all(|&x| x == 0) {
        let error = vec![0u8; MCELIECE_N / 8];
        return Ok(hash_error(&error));
    }

    let error_locator = berlekamp_massey(&syndrome);
    let error_positions = chien_search(&error_locator, &sk.support);
    if error_positions.len() > MCELIECE_T {
        return Err("Too many errors to correct");
    }

    let mut error = vec![0u8; MCELIECE_N / 8];
    for &pos in &error_positions {
        if pos < MCELIECE_N {
            let orig_pos = sk.permutation.iter().position(|&p| p as usize == pos).unwrap_or(pos);
            error[orig_pos / 8] |= 1 << (orig_pos % 8);
        }
    }

    let shared_secret = hash_error(&error);
    Ok(shared_secret)
}
