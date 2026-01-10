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
use super::address::{Address, ADDR_TYPE_FORS_PRF, ADDR_TYPE_FORS_ROOTS, ADDR_TYPE_FORS_TREE};
use super::hash::{prf, thash};
use super::{SPHINCS_A, SPHINCS_K, SPHINCS_N, SPHINCS_FORS_SIG_BYTES};

fn extract_fors_index(msg: &[u8], tree: usize) -> u32 {
    let bit_offset = tree * SPHINCS_A;
    let byte_offset = bit_offset / 8;
    let bit_shift = bit_offset % 8;
    let mut idx = 0u32;
    for i in 0..((SPHINCS_A + 7) / 8) {
        if byte_offset + i < msg.len() {
            idx |= (msg[byte_offset + i] as u32) << (8 * i);
        }
    }
    (idx >> bit_shift) & ((1 << SPHINCS_A) - 1)
}

fn fors_tree_node(
    sk_seed: &[u8; SPHINCS_N],
    pk_seed: &[u8; SPHINCS_N],
    addr: &mut Address,
    idx: u32,
    height: u32,
) -> [u8; SPHINCS_N] {
    if height == 0 {
        addr.set_type(ADDR_TYPE_FORS_PRF);
        addr.set_tree_index(idx);
        let sk = prf(sk_seed, pk_seed, addr);

        addr.set_type(ADDR_TYPE_FORS_TREE);
        addr.set_tree_height(0);
        thash(pk_seed, addr, &sk)
    } else {
        let left = fors_tree_node(sk_seed, pk_seed, addr, 2 * idx, height - 1);
        let right = fors_tree_node(sk_seed, pk_seed, addr, 2 * idx + 1, height - 1);

        addr.set_tree_height(height);
        addr.set_tree_index(idx);

        let mut concat = [0u8; 2 * SPHINCS_N];
        concat[..SPHINCS_N].copy_from_slice(&left);
        concat[SPHINCS_N..].copy_from_slice(&right);

        thash(pk_seed, addr, &concat)
    }
}

pub fn fors_sign(
    sk_seed: &[u8; SPHINCS_N],
    pk_seed: &[u8; SPHINCS_N],
    msg: &[u8],
    addr: &mut Address,
) -> Vec<u8> {
    let mut sig = Vec::with_capacity(SPHINCS_FORS_SIG_BYTES);
    for i in 0..SPHINCS_K {
        let idx = extract_fors_index(msg, i);
        addr.set_tree_height(0);
        addr.set_tree_index(idx + (i as u32) * (1 << SPHINCS_A));
        addr.set_type(ADDR_TYPE_FORS_PRF);

        let sk = prf(sk_seed, pk_seed, addr);
        sig.extend_from_slice(&sk);
        addr.set_type(ADDR_TYPE_FORS_TREE);
        for j in 0..SPHINCS_A {
            let sibling = ((idx >> j) ^ 1) + (i as u32) * (1 << SPHINCS_A);
            addr.set_tree_index(sibling);
            addr.set_tree_height(j as u32);
            let node = fors_tree_node(sk_seed, pk_seed, addr, sibling, j as u32);
            sig.extend_from_slice(&node);
        }
    }

    sig
}

pub fn fors_pk_from_sig(
    pk_seed: &[u8; SPHINCS_N],
    sig: &[u8],
    msg: &[u8],
    addr: &mut Address,
) -> [u8; SPHINCS_N] {
    let mut roots = Vec::with_capacity(SPHINCS_K * SPHINCS_N);
    let sig_per_tree = (1 + SPHINCS_A) * SPHINCS_N;
    for i in 0..SPHINCS_K {
        let idx = extract_fors_index(msg, i);
        let tree_sig = &sig[i * sig_per_tree..(i + 1) * sig_per_tree];
        addr.set_type(ADDR_TYPE_FORS_TREE);
        addr.set_tree_height(0);
        addr.set_tree_index(idx + (i as u32) * (1 << SPHINCS_A));

        let mut sk = [0u8; SPHINCS_N];
        sk.copy_from_slice(&tree_sig[0..SPHINCS_N]);
        let mut node = thash(pk_seed, addr, &sk);
        let mut cur_idx = idx;
        for j in 0..SPHINCS_A {
            let auth_offset = (1 + j) * SPHINCS_N;
            let mut auth_node = [0u8; SPHINCS_N];
            auth_node.copy_from_slice(&tree_sig[auth_offset..auth_offset + SPHINCS_N]);

            addr.set_tree_height((j + 1) as u32);
            let parent_idx = cur_idx / 2;
            addr.set_tree_index(parent_idx + (i as u32) * (1 << (SPHINCS_A - j - 1)));

            let mut concat = [0u8; 2 * SPHINCS_N];
            if cur_idx % 2 == 0 {
                concat[..SPHINCS_N].copy_from_slice(&node);
                concat[SPHINCS_N..].copy_from_slice(&auth_node);
            } else {
                concat[..SPHINCS_N].copy_from_slice(&auth_node);
                concat[SPHINCS_N..].copy_from_slice(&node);
            }

            node = thash(pk_seed, addr, &concat);
            cur_idx = parent_idx;
        }

        roots.extend_from_slice(&node);
    }

    addr.set_type(ADDR_TYPE_FORS_ROOTS);
    thash(pk_seed, addr, &roots)
}
