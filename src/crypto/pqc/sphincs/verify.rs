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

use super::address::{Address, ADDR_TYPE_TREE};
use super::fors::fors_pk_from_sig;
use super::hash::{hash_message, thash};
use super::wots::wots_pk_from_sig;
use super::{
    SphincsPublicKey, SphincsSignature,
    SPHINCS_D, SPHINCS_FORS_SIG_BYTES, SPHINCS_H, SPHINCS_N, SPHINCS_WOTS_SIG_BYTES,
};

pub fn sphincs_verify(pk: &SphincsPublicKey, msg: &[u8], sig: &SphincsSignature) -> bool {
    if sig.bytes.len() < SPHINCS_N + SPHINCS_FORS_SIG_BYTES {
        return false;
    }

    let mut r = [0u8; SPHINCS_N];
    r.copy_from_slice(&sig.bytes[0..SPHINCS_N]);

    let (fors_msg, tree_idx, leaf_idx) = hash_message(&r, &pk.seed, &pk.root, msg);
    let mut addr = Address::default();
    addr.set_tree(tree_idx);
    addr.set_keypair(leaf_idx);

    let fors_sig = &sig.bytes[SPHINCS_N..SPHINCS_N + SPHINCS_FORS_SIG_BYTES];
    let fors_pk = fors_pk_from_sig(&pk.seed, fors_sig, &fors_msg, &mut addr);
    let mut node = fors_pk;
    let layer_height = SPHINCS_H / SPHINCS_D;
    let mut offset = SPHINCS_N + SPHINCS_FORS_SIG_BYTES;
    for layer in 0..SPHINCS_D {
        if offset + SPHINCS_WOTS_SIG_BYTES + layer_height * SPHINCS_N > sig.bytes.len() {
            return false;
        }

        addr.set_layer(layer as u32);
        addr.set_tree(tree_idx >> (layer * layer_height));
        addr.set_keypair((leaf_idx >> ((layer * layer_height) as u32)) & ((1 << layer_height) - 1) as u32);

        let wots_sig = &sig.bytes[offset..offset + SPHINCS_WOTS_SIG_BYTES];
        offset += SPHINCS_WOTS_SIG_BYTES;

        node = wots_pk_from_sig(&pk.seed, wots_sig, &node, &mut addr);

        let current_leaf = (leaf_idx >> ((layer * layer_height) as u32)) & ((1 << layer_height) - 1) as u32;
        for height in 0..layer_height {
            let auth_offset = offset + height * SPHINCS_N;
            let mut auth_node = [0u8; SPHINCS_N];
            auth_node.copy_from_slice(&sig.bytes[auth_offset..auth_offset + SPHINCS_N]);

            addr.set_tree_height((height + 1) as u32);
            let parent_idx = (current_leaf >> height) / 2;
            addr.set_tree_index(parent_idx);
            addr.set_type(ADDR_TYPE_TREE);

            let mut concat = [0u8; 2 * SPHINCS_N];
            if ((current_leaf >> height) & 1) == 0 {
                concat[..SPHINCS_N].copy_from_slice(&node);
                concat[SPHINCS_N..].copy_from_slice(&auth_node);
            } else {
                concat[..SPHINCS_N].copy_from_slice(&auth_node);
                concat[SPHINCS_N..].copy_from_slice(&node);
            }

            node = thash(&pk.seed, &addr, &concat);
        }
        offset += layer_height * SPHINCS_N;
    }

    crate::crypto::constant_time::ct_eq(&node, &pk.root)
}
