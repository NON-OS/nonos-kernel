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
use crate::crypto::sha3::shake256;
use super::address::Address;
use super::{SPHINCS_FORS_MSG_BYTES, SPHINCS_H, SPHINCS_D, SPHINCS_N};

pub fn thash(pk_seed: &[u8; SPHINCS_N], addr: &Address, input: &[u8]) -> [u8; SPHINCS_N] {
    let addr_bytes = addr.to_bytes();
    let mut hasher_input = Vec::with_capacity(SPHINCS_N + 32 + input.len());
    hasher_input.extend_from_slice(pk_seed);
    hasher_input.extend_from_slice(&addr_bytes);
    hasher_input.extend_from_slice(input);

    let hash = shake256(&hasher_input, SPHINCS_N);
    let mut out = [0u8; SPHINCS_N];
    out.copy_from_slice(&hash[..SPHINCS_N]);
    out
}

pub fn prf(sk_seed: &[u8; SPHINCS_N], pk_seed: &[u8; SPHINCS_N], addr: &Address) -> [u8; SPHINCS_N] {
    let addr_bytes = addr.to_bytes();
    let mut input = Vec::with_capacity(2 * SPHINCS_N + 32);
    input.extend_from_slice(pk_seed);
    input.extend_from_slice(&addr_bytes);
    input.extend_from_slice(sk_seed);

    let hash = shake256(&input, SPHINCS_N);
    let mut out = [0u8; SPHINCS_N];
    out.copy_from_slice(&hash[..SPHINCS_N]);
    out
}

pub fn prf_msg(sk_prf: &[u8; SPHINCS_N], opt_rand: &[u8; SPHINCS_N], msg: &[u8]) -> [u8; SPHINCS_N] {
    let mut input = Vec::with_capacity(2 * SPHINCS_N + msg.len());
    input.extend_from_slice(sk_prf);
    input.extend_from_slice(opt_rand);
    input.extend_from_slice(msg);

    let hash = shake256(&input, SPHINCS_N);
    let mut out = [0u8; SPHINCS_N];
    out.copy_from_slice(&hash[..SPHINCS_N]);
    out
}

pub fn hash_message(
    r: &[u8; SPHINCS_N],
    pk_seed: &[u8; SPHINCS_N],
    pk_root: &[u8; SPHINCS_N],
    msg: &[u8],
) -> (Vec<u8>, u64, u32) {
    let mut input = Vec::with_capacity(3 * SPHINCS_N + msg.len());
    input.extend_from_slice(r);
    input.extend_from_slice(pk_seed);
    input.extend_from_slice(pk_root);
    input.extend_from_slice(msg);

    let out_len = SPHINCS_FORS_MSG_BYTES + 8 + 4;
    let digest = shake256(&input, out_len);
    let fors_msg = digest[0..SPHINCS_FORS_MSG_BYTES].to_vec();
    let mut tree_bytes = [0u8; 8];
    tree_bytes.copy_from_slice(&digest[SPHINCS_FORS_MSG_BYTES..SPHINCS_FORS_MSG_BYTES + 8]);
    let tree_idx = u64::from_be_bytes(tree_bytes) & ((1u64 << (SPHINCS_H - SPHINCS_H / SPHINCS_D)) - 1);
    let mut leaf_bytes = [0u8; 4];
    leaf_bytes.copy_from_slice(&digest[SPHINCS_FORS_MSG_BYTES + 8..SPHINCS_FORS_MSG_BYTES + 12]);
    let leaf_idx = u32::from_be_bytes(leaf_bytes) & ((1u32 << (SPHINCS_H / SPHINCS_D)) - 1);

    (fors_msg, tree_idx, leaf_idx)
}
