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

use crate::crypto::asymmetric::secp256k1;
use core::sync::atomic::{AtomicU64, Ordering};

static SIGN_COUNT: AtomicU64 = AtomicU64::new(0);
static VERIFY_COUNT: AtomicU64 = AtomicU64::new(0);
static KEYGEN_COUNT: AtomicU64 = AtomicU64::new(0);
static ECDH_COUNT: AtomicU64 = AtomicU64::new(0);

pub(super) fn keygen(privkey: &mut [u8; 32], pubkey: &mut [u8; 33]) {
    let (sk, pk) = secp256k1::generate_keypair();
    privkey.copy_from_slice(&sk);
    pubkey.copy_from_slice(&pk[..33]);
    KEYGEN_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub(super) fn sign_ecdsa(privkey: &[u8; 32], message_hash: &[u8; 32], signature: &mut [u8; 64]) {
    if let Some(sig) = secp256k1::sign(privkey, message_hash) {
        signature.copy_from_slice(&sig.to_bytes()[..64]);
    }
    SIGN_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub(super) fn verify_ecdsa(
    pubkey: &[u8; 33],
    message_hash: &[u8; 32],
    signature: &[u8; 64],
) -> bool {
    if let Ok(pk) = secp256k1::decompress_pubkey(pubkey) {
        let result = secp256k1::verify(&pk, message_hash, signature);
        VERIFY_COUNT.fetch_add(1, Ordering::Relaxed);
        return result;
    }
    VERIFY_COUNT.fetch_add(1, Ordering::Relaxed);
    false
}

pub(super) fn ecdh(privkey: &[u8; 32], pubkey: &[u8; 33], shared: &mut [u8; 32]) {
    if let Ok(pk) = secp256k1::decompress_pubkey(pubkey) {
        if let Ok(result) = secp256k1::multiply_point(&pk, privkey) {
            shared.copy_from_slice(&result[1..33]);
        }
    }
    ECDH_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub(super) fn get_stats() -> (u64, u64, u64, u64) {
    (
        SIGN_COUNT.load(Ordering::Relaxed),
        VERIFY_COUNT.load(Ordering::Relaxed),
        KEYGEN_COUNT.load(Ordering::Relaxed),
        ECDH_COUNT.load(Ordering::Relaxed),
    )
}
