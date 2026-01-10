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
use crate::crypto::rng;
use super::address::Address;
use super::fors::{fors_pk_from_sig, fors_sign};
use super::hash::{hash_message, prf_msg};
use super::hypertree::compute_auth_path;
use super::wots::{wots_pk_gen, wots_sign};
use super::{
    SphincsKeyPair, SphincsPublicKey, SphincsSecretKey, SphincsSignature,
    SPHINCS_D, SPHINCS_H, SPHINCS_N, SPHINCS_SIG_BYTES,
};

pub fn sphincs_keygen() -> Result<SphincsKeyPair, &'static str> {
    let mut sk_seed = [0u8; SPHINCS_N];
    let mut sk_prf = [0u8; SPHINCS_N];
    let mut pk_seed = [0u8; SPHINCS_N];

    rng::fill_random_bytes(&mut sk_seed);
    rng::fill_random_bytes(&mut sk_prf);
    rng::fill_random_bytes(&mut pk_seed);

    let mut addr = Address::default();
    addr.set_layer((SPHINCS_D - 1) as u32);
    let pk_root = wots_pk_gen(&sk_seed, &pk_seed, &mut addr);

    Ok(SphincsKeyPair {
        public_key: SphincsPublicKey {
            seed: pk_seed,
            root: pk_root,
        },
        secret_key: SphincsSecretKey {
            sk_seed,
            sk_prf,
            pk_seed,
            pk_root,
        },
    })
}

pub fn sphincs_sign(sk: &SphincsSecretKey, msg: &[u8]) -> Result<SphincsSignature, &'static str> {
    let mut sig = Vec::with_capacity(SPHINCS_SIG_BYTES);
    let mut opt_rand = [0u8; SPHINCS_N];
    rng::fill_random_bytes(&mut opt_rand);
    let r = prf_msg(&sk.sk_prf, &opt_rand, msg);
    sig.extend_from_slice(&r);

    let (fors_msg, tree_idx, leaf_idx) = hash_message(&r, &sk.pk_seed, &sk.pk_root, msg);
    let mut addr = Address::default();
    addr.set_tree(tree_idx);
    addr.set_keypair(leaf_idx);
    let fors_sig = fors_sign(&sk.sk_seed, &sk.pk_seed, &fors_msg, &mut addr);
    sig.extend_from_slice(&fors_sig);

    let fors_pk = fors_pk_from_sig(&sk.pk_seed, &fors_sig, &fors_msg, &mut addr);
    let mut node = fors_pk;
    let layer_height = SPHINCS_H / SPHINCS_D;
    for layer in 0..SPHINCS_D {
        addr.set_layer(layer as u32);
        addr.set_tree(tree_idx >> (layer * layer_height));
        addr.set_keypair((leaf_idx >> ((layer * layer_height) as u32)) & ((1 << layer_height) - 1) as u32);

        let wots_sig = wots_sign(&sk.sk_seed, &sk.pk_seed, &node, &mut addr);
        sig.extend_from_slice(&wots_sig);

        let current_leaf = (leaf_idx >> ((layer * layer_height) as u32)) & ((1 << layer_height) - 1) as u32;
        let auth_path = compute_auth_path(&sk.sk_seed, &sk.pk_seed, current_leaf, layer_height, &mut addr);
        sig.extend_from_slice(&auth_path);

        node = wots_pk_gen(&sk.sk_seed, &sk.pk_seed, &mut addr);
    }

    Ok(SphincsSignature { bytes: sig })
}
