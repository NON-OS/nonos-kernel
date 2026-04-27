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

use crate::crypto::asymmetric::ed25519::{
    sign as ed_sign, verify as ed_verify, KeyPair, Signature,
};
use core::sync::atomic::{AtomicU64, Ordering};

static SIGN_COUNT: AtomicU64 = AtomicU64::new(0);
static VERIFY_COUNT: AtomicU64 = AtomicU64::new(0);
static KEYGEN_COUNT: AtomicU64 = AtomicU64::new(0);

pub(super) fn generate_keypair(seed: &[u8; 32], pubkey: &mut [u8; 32], privkey: &mut [u8; 64]) {
    let kp = KeyPair::from_seed(*seed);
    pubkey.copy_from_slice(&kp.public);
    privkey[..32].copy_from_slice(&kp.private);
    privkey[32..].copy_from_slice(&kp.public);
    KEYGEN_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub(super) fn sign(privkey: &[u8; 64], message: &[u8], signature: &mut [u8; 64]) {
    let kp = KeyPair {
        private: {
            let mut a = [0u8; 32];
            a.copy_from_slice(&privkey[..32]);
            a
        },
        public: {
            let mut a = [0u8; 32];
            a.copy_from_slice(&privkey[32..]);
            a
        },
    };
    let sig = ed_sign(&kp, message);
    *signature = sig.to_bytes();
    SIGN_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub(super) fn verify(pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let sig = Signature::from_bytes(signature);
    let result = ed_verify(pubkey, message, &sig);
    VERIFY_COUNT.fetch_add(1, Ordering::Relaxed);
    result
}

pub(super) fn public_key_from_private(privkey: &[u8; 64], pubkey: &mut [u8; 32]) {
    pubkey.copy_from_slice(&privkey[32..]);
}

pub(super) fn get_stats() -> (u64, u64, u64) {
    (
        SIGN_COUNT.load(Ordering::Relaxed),
        VERIFY_COUNT.load(Ordering::Relaxed),
        KEYGEN_COUNT.load(Ordering::Relaxed),
    )
}
