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
use core::ptr;

use crate::crypto::hash::sha256;
use crate::crypto::util::constant_time::{compiler_fence, memory_fence};
use crate::crypto::rng::get_random_bytes;
use crate::crypto::ed25519::{KeyPair, Signature as EdSig, sign as ed25519_sign, verify as ed25519_verify};

use super::constants::DOM_ATTEST;
use super::types::AttestationProof;

pub fn create_attestation(data: &[u8], keypair: &KeyPair) -> AttestationProof {
    let msg_hash = sha256(data);
    let nonce = get_random_bytes();

    let mut t = Vec::with_capacity(DOM_ATTEST.len() + 32 + 32);
    t.extend_from_slice(DOM_ATTEST);
    t.extend_from_slice(&msg_hash);
    t.extend_from_slice(&nonce);

    let sig = ed25519_sign(keypair, &t).to_bytes();

    for b in t.iter_mut() {
        unsafe { ptr::write_volatile(b, 0) };
    }
    compiler_fence();
    memory_fence();

    AttestationProof {
        msg_hash,
        nonce,
        signature: sig,
        pubkey: keypair.public,
    }
}

pub fn verify_attestation(
    data: &[u8],
    expected_pubkey: &[u8; 32],
    proof: &AttestationProof,
) -> bool {
    if sha256(data) != proof.msg_hash {
        return false;
    }
    if &proof.pubkey != expected_pubkey {
        return false;
    }

    let mut t = Vec::with_capacity(DOM_ATTEST.len() + 32 + 32);
    t.extend_from_slice(DOM_ATTEST);
    t.extend_from_slice(&proof.msg_hash);
    t.extend_from_slice(&proof.nonce);

    let sig = EdSig::from_bytes(&proof.signature);
    let ok = ed25519_verify(expected_pubkey, &t, &sig);

    for b in t.iter_mut() {
        unsafe { ptr::write_volatile(b, 0) };
    }
    compiler_fence();
    memory_fence();

    ok
}
