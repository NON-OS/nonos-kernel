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
use super::rlp::*;
use crate::crypto::{keccak256, secp256k1::sign_recoverable};
use alloc::vec::Vec;

pub(super) fn build_and_sign_tx(
    to: &[u8; 20],
    val: u128,
    nonce: u64,
    gp: u128,
    gl: u64,
    cid: u64,
    sk: &[u8; 32],
) -> Result<Vec<u8>, &'static [u8]> {
    let mut items = Vec::new();
    items.push(rlp_encode_u64(nonce));
    items.push(rlp_encode_u128(gp));
    items.push(rlp_encode_u64(gl));
    items.push(rlp_encode_bytes(to));
    items.push(rlp_encode_u128(val));
    items.push(rlp_encode_bytes(&[]));
    items.push(rlp_encode_u64(cid));
    items.push(rlp_encode_bytes(&[]));
    items.push(rlp_encode_bytes(&[]));
    let hash = keccak256(&rlp_encode_list(&items));
    let sig = sign_recoverable(sk, &hash).ok_or(b"Sign failed" as &[u8])?;
    let v = (sig.recovery_id as u64) + 35 + cid * 2;
    let mut si = Vec::new();
    si.push(rlp_encode_u64(nonce));
    si.push(rlp_encode_u128(gp));
    si.push(rlp_encode_u64(gl));
    si.push(rlp_encode_bytes(to));
    si.push(rlp_encode_u128(val));
    si.push(rlp_encode_bytes(&[]));
    si.push(rlp_encode_u64(v));
    si.push(rlp_encode_bytes(&sig.r));
    si.push(rlp_encode_bytes(&sig.s));
    Ok(rlp_encode_list(&si))
}

pub(super) fn build_and_sign_contract_tx(
    to: &[u8; 20],
    val: u128,
    data: &[u8],
    nonce: u64,
    gp: u128,
    gl: u64,
    cid: u64,
    sk: &[u8; 32],
) -> Result<Vec<u8>, &'static [u8]> {
    let mut items = Vec::new();
    items.push(rlp_encode_u64(nonce));
    items.push(rlp_encode_u128(gp));
    items.push(rlp_encode_u64(gl));
    items.push(rlp_encode_bytes(to));
    items.push(rlp_encode_u128(val));
    items.push(rlp_encode_bytes(data));
    items.push(rlp_encode_u64(cid));
    items.push(rlp_encode_bytes(&[]));
    items.push(rlp_encode_bytes(&[]));
    let hash = keccak256(&rlp_encode_list(&items));
    let sig = sign_recoverable(sk, &hash).ok_or(b"Sign failed" as &[u8])?;
    let v = (sig.recovery_id as u64) + 35 + cid * 2;
    let mut si = Vec::new();
    si.push(rlp_encode_u64(nonce));
    si.push(rlp_encode_u128(gp));
    si.push(rlp_encode_u64(gl));
    si.push(rlp_encode_bytes(to));
    si.push(rlp_encode_u128(val));
    si.push(rlp_encode_bytes(data));
    si.push(rlp_encode_u64(v));
    si.push(rlp_encode_bytes(&sig.r));
    si.push(rlp_encode_bytes(&sig.s));
    Ok(rlp_encode_list(&si))
}
