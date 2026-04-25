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

use crate::crypto::pqc::quantum::{dilithium3_keypair, dilithium3_sign, dilithium3_verify};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static KEYGEN_COUNT: AtomicU64 = AtomicU64::new(0);
static SIGN_COUNT: AtomicU64 = AtomicU64::new(0);
static VERIFY_COUNT: AtomicU64 = AtomicU64::new(0);

pub(super) fn keygen() -> Option<(Vec<u8>, Vec<u8>)> {
    let result = dilithium3_keypair().ok();
    if result.is_some() {
        KEYGEN_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    result
}

pub(super) fn sign(message: &[u8], sk: &[u8]) -> Option<Vec<u8>> {
    let result = dilithium3_sign(message, sk).ok();
    if result.is_some() {
        SIGN_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    result
}

pub(super) fn verify(message: &[u8], sig: &[u8], pk: &[u8]) -> bool {
    let result = dilithium3_verify(message, sig, pk);
    VERIFY_COUNT.fetch_add(1, Ordering::Relaxed);
    result
}

pub(super) fn get_stats() -> (u64, u64, u64) {
    (
        KEYGEN_COUNT.load(Ordering::Relaxed),
        SIGN_COUNT.load(Ordering::Relaxed),
        VERIFY_COUNT.load(Ordering::Relaxed),
    )
}
