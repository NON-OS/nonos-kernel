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

use crate::crypto::pqc::quantum::{kyber1024_decapsulate, kyber768_decapsulate};
use crate::crypto::pqc::quantum::{kyber1024_encapsulate, kyber768_encapsulate};
use crate::crypto::pqc::quantum::{kyber1024_keypair, kyber768_keypair};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static KEYGEN_COUNT: AtomicU64 = AtomicU64::new(0);
static ENCAPS_COUNT: AtomicU64 = AtomicU64::new(0);
static DECAPS_COUNT: AtomicU64 = AtomicU64::new(0);

pub(super) fn keygen_768() -> Option<(Vec<u8>, Vec<u8>)> {
    let result = kyber768_keypair().ok();
    if result.is_some() {
        KEYGEN_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    result
}

pub(super) fn keygen_1024() -> Option<(Vec<u8>, Vec<u8>)> {
    let result = kyber1024_keypair().ok();
    if result.is_some() {
        KEYGEN_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    result
}

pub(super) fn encapsulate_768(pk: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let result = kyber768_encapsulate(pk).ok();
    if result.is_some() {
        ENCAPS_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    result
}

pub(super) fn encapsulate_1024(pk: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let result = kyber1024_encapsulate(pk).ok();
    if result.is_some() {
        ENCAPS_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    result
}

pub(super) fn decapsulate_768(ct: &[u8], sk: &[u8]) -> Option<Vec<u8>> {
    let result = kyber768_decapsulate(ct, sk).ok();
    if result.is_some() {
        DECAPS_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    result
}

pub(super) fn decapsulate_1024(ct: &[u8], sk: &[u8]) -> Option<Vec<u8>> {
    let result = kyber1024_decapsulate(ct, sk).ok();
    if result.is_some() {
        DECAPS_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    result
}

pub(super) fn get_stats() -> (u64, u64, u64) {
    (
        KEYGEN_COUNT.load(Ordering::Relaxed),
        ENCAPS_COUNT.load(Ordering::Relaxed),
        DECAPS_COUNT.load(Ordering::Relaxed),
    )
}
