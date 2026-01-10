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
use super::address::{Address, ADDR_TYPE_WOTS, ADDR_TYPE_WOTS_PK, ADDR_TYPE_WOTS_PRF};
use super::hash::{prf, thash};
use super::{SPHINCS_N, SPHINCS_W, SPHINCS_WOTS_LEN, SPHINCS_WOTS_LEN1, SPHINCS_WOTS_LEN2, SPHINCS_WOTS_SIG_BYTES};

fn wots_chain(
    pk_seed: &[u8; SPHINCS_N],
    addr: &mut Address,
    x: &[u8; SPHINCS_N],
    start: u32,
    steps: u32,
) -> [u8; SPHINCS_N] {
    let mut out = *x;
    for i in start..(start + steps) {
        addr.set_hash(i);
        out = thash(pk_seed, addr, &out);
    }
    out
}

pub fn wots_pk_gen(
    sk_seed: &[u8; SPHINCS_N],
    pk_seed: &[u8; SPHINCS_N],
    addr: &mut Address,
) -> [u8; SPHINCS_N] {
    let mut tmp = Vec::with_capacity(SPHINCS_WOTS_LEN * SPHINCS_N);

    addr.set_type(ADDR_TYPE_WOTS_PRF);

    for i in 0..SPHINCS_WOTS_LEN {
        addr.set_chain(i as u32);
        let sk = prf(sk_seed, pk_seed, addr);

        addr.set_type(ADDR_TYPE_WOTS);
        let pk_i = wots_chain(pk_seed, addr, &sk, 0, (SPHINCS_W - 1) as u32);
        tmp.extend_from_slice(&pk_i);

        addr.set_type(ADDR_TYPE_WOTS_PRF);
    }

    addr.set_type(ADDR_TYPE_WOTS_PK);
    thash(pk_seed, addr, &tmp)
}

pub fn wots_sign(
    sk_seed: &[u8; SPHINCS_N],
    pk_seed: &[u8; SPHINCS_N],
    msg: &[u8; SPHINCS_N],
    addr: &mut Address,
) -> Vec<u8> {
    let mut sig = Vec::with_capacity(SPHINCS_WOTS_SIG_BYTES);

    let mut base_w = [0u32; SPHINCS_WOTS_LEN];
    let mut csum = 0u32;

    for i in 0..SPHINCS_WOTS_LEN1 {
        let byte_idx = i / 2;
        let bit_shift = if i % 2 == 0 { 4 } else { 0 };
        base_w[i] = ((msg[byte_idx] >> bit_shift) & 0x0F) as u32;
        csum += (SPHINCS_W as u32 - 1) - base_w[i];
    }

    csum <<= 4;
    for i in 0..SPHINCS_WOTS_LEN2 {
        base_w[SPHINCS_WOTS_LEN1 + i] = (csum >> (4 * (SPHINCS_WOTS_LEN2 - 1 - i))) & 0x0F;
    }

    addr.set_type(ADDR_TYPE_WOTS_PRF);

    for i in 0..SPHINCS_WOTS_LEN {
        addr.set_chain(i as u32);
        let sk = prf(sk_seed, pk_seed, addr);

        addr.set_type(ADDR_TYPE_WOTS);
        let sig_i = wots_chain(pk_seed, addr, &sk, 0, base_w[i]);
        sig.extend_from_slice(&sig_i);

        addr.set_type(ADDR_TYPE_WOTS_PRF);
    }

    sig
}

pub fn wots_pk_from_sig(
    pk_seed: &[u8; SPHINCS_N],
    sig: &[u8],
    msg: &[u8; SPHINCS_N],
    addr: &mut Address,
) -> [u8; SPHINCS_N] {
    let mut tmp = Vec::with_capacity(SPHINCS_WOTS_LEN * SPHINCS_N);

    let mut base_w = [0u32; SPHINCS_WOTS_LEN];
    let mut csum = 0u32;

    for i in 0..SPHINCS_WOTS_LEN1 {
        let byte_idx = i / 2;
        let bit_shift = if i % 2 == 0 { 4 } else { 0 };
        base_w[i] = ((msg[byte_idx] >> bit_shift) & 0x0F) as u32;
        csum += (SPHINCS_W as u32 - 1) - base_w[i];
    }

    csum <<= 4;
    for i in 0..SPHINCS_WOTS_LEN2 {
        base_w[SPHINCS_WOTS_LEN1 + i] = (csum >> (4 * (SPHINCS_WOTS_LEN2 - 1 - i))) & 0x0F;
    }

    addr.set_type(ADDR_TYPE_WOTS);

    for i in 0..SPHINCS_WOTS_LEN {
        addr.set_chain(i as u32);
        let mut sig_i = [0u8; SPHINCS_N];
        sig_i.copy_from_slice(&sig[i * SPHINCS_N..(i + 1) * SPHINCS_N]);

        let pk_i = wots_chain(pk_seed, addr, &sig_i, base_w[i], (SPHINCS_W as u32 - 1) - base_w[i]);
        tmp.extend_from_slice(&pk_i);
    }

    addr.set_type(ADDR_TYPE_WOTS_PK);
    thash(pk_seed, addr, &tmp)
}
