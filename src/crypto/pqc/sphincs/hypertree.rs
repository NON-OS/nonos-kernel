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
use super::address::{Address, ADDR_TYPE_TREE};
use super::hash::thash;
use super::wots::wots_pk_gen;
use super::SPHINCS_N;

pub fn treehash(
    sk_seed: &[u8; SPHINCS_N],
    pk_seed: &[u8; SPHINCS_N],
    leaf_idx: u32,
    target_height: u32,
    addr: &mut Address,
) -> [u8; SPHINCS_N] {
    if target_height == 0 {
        addr.set_keypair(leaf_idx);
        return wots_pk_gen(sk_seed, pk_seed, addr);
    }

    let left = treehash(sk_seed, pk_seed, 2 * leaf_idx, target_height - 1, addr);
    let right = treehash(sk_seed, pk_seed, 2 * leaf_idx + 1, target_height - 1, addr);

    addr.set_tree_height(target_height);
    addr.set_tree_index(leaf_idx);
    addr.set_type(ADDR_TYPE_TREE);

    let mut concat = [0u8; 2 * SPHINCS_N];
    concat[..SPHINCS_N].copy_from_slice(&left);
    concat[SPHINCS_N..].copy_from_slice(&right);

    thash(pk_seed, addr, &concat)
}

pub fn compute_auth_path(
    sk_seed: &[u8; SPHINCS_N],
    pk_seed: &[u8; SPHINCS_N],
    leaf_idx: u32,
    tree_height: usize,
    addr: &mut Address,
) -> Vec<u8> {
    let mut auth_path = Vec::with_capacity(tree_height * SPHINCS_N);
    for height in 0..tree_height {
        let sibling_idx = (leaf_idx >> height) ^ 1;
        let node = treehash(sk_seed, pk_seed, sibling_idx, height as u32, addr);
        auth_path.extend_from_slice(&node);
    }

    auth_path
}
