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

use crate::crypto::hash::blake3_hash;
use crate::crypto::util::constant_time::{compiler_fence, memory_fence};
use crate::crypto::rng::random_u64;
use crate::crypto::ed25519::{KeyPair, Signature as EdSig, sign as ed25519_sign, verify as ed25519_verify};

use super::constants::DOM_CRED;
use super::types::Credential;

impl Credential {
    pub(crate) fn transcript_digest(&self) -> [u8; 32] {
        let mut t = Vec::with_capacity(DOM_CRED.len() + 32 + 32 + 32 + 8);
        t.extend_from_slice(DOM_CRED);
        t.extend_from_slice(&self.id);
        t.extend_from_slice(&self.subject_pubkey);
        t.extend_from_slice(&self.attrs_hash);
        t.extend_from_slice(&self.timestamp.to_le_bytes());
        let h = blake3_hash(&t);
        for b in t.iter_mut() {
            unsafe { ptr::write_volatile(b, 0) };
        }
        compiler_fence();
        memory_fence();
        h
    }
}

pub fn issue_credential(
    issuer: &KeyPair,
    subject_pubkey: &[u8; 32],
    attributes: &[u8],
    timestamp: u64,
) -> Credential {
    let attrs_hash = blake3_hash(attributes);

    let mut id_t = Vec::with_capacity(32 + 32 + 8 + 16);
    id_t.extend_from_slice(subject_pubkey);
    id_t.extend_from_slice(&attrs_hash);
    id_t.extend_from_slice(&timestamp.to_le_bytes());
    id_t.extend_from_slice(&random_u64().to_le_bytes());
    id_t.extend_from_slice(&random_u64().to_le_bytes());
    let id = blake3_hash(&id_t);
    for b in id_t.iter_mut() {
        unsafe { ptr::write_volatile(b, 0) };
    }
    compiler_fence();
    memory_fence();

    let mut cred = Credential {
        id,
        subject_pubkey: *subject_pubkey,
        attrs_hash,
        timestamp,
        signature: [0u8; 64],
        issuer_pubkey: issuer.public,
    };

    let digest = cred.transcript_digest();
    let sig = ed25519_sign(issuer, &digest).to_bytes();
    cred.signature = sig;

    let mut d = [0u8; 32];
    d.copy_from_slice(&digest);
    for b in d.iter_mut() {
        unsafe { ptr::write_volatile(b, 0) };
    }
    compiler_fence();
    memory_fence();

    cred
}

pub fn verify_credential(cred: &Credential) -> bool {
    let digest = cred.transcript_digest();
    let sig = EdSig::from_bytes(&cred.signature);
    let ok = ed25519_verify(&cred.issuer_pubkey, &digest, &sig);

    let mut d = [0u8; 32];
    d.copy_from_slice(&digest);
    for b in d.iter_mut() {
        unsafe { ptr::write_volatile(b, 0) };
    }
    compiler_fence();
    memory_fence();

    ok
}
