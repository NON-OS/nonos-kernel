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

mod kat;
mod metadata;
mod selftest;

pub use kat::*;
pub use metadata::*;
pub use selftest::*;

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificationStatus {
    Certified,
    NotTested,
    Failed,
    Degraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmStatus {
    Pass,
    Fail,
    Pending,
    Unavailable,
}

pub struct CryptoState {
    pub sha3_256: AtomicBool,
    pub blake3: AtomicBool,
    pub chacha20poly1305: AtomicBool,
    pub ed25519: AtomicBool,
    pub rng: AtomicBool,
    pub sphincs: AtomicBool,
    pub ntru: AtomicBool,
    pub overall_tests_run: AtomicBool,
    pub tests_passed: AtomicU32,
    pub tests_failed: AtomicU32,
}

impl CryptoState {
    pub const fn new() -> Self {
        Self {
            sha3_256: AtomicBool::new(false),
            blake3: AtomicBool::new(false),
            chacha20poly1305: AtomicBool::new(false),
            ed25519: AtomicBool::new(false),
            rng: AtomicBool::new(false),
            sphincs: AtomicBool::new(false),
            ntru: AtomicBool::new(false),
            overall_tests_run: AtomicBool::new(false),
            tests_passed: AtomicU32::new(0),
            tests_failed: AtomicU32::new(0),
        }
    }
}

pub static CRYPTO_STATE: CryptoState = CryptoState::new();
pub fn get_certification_status() -> CertificationStatus {
    if !CRYPTO_STATE.overall_tests_run.load(Ordering::SeqCst) {
        return CertificationStatus::NotTested;
    }

    let failed = CRYPTO_STATE.tests_failed.load(Ordering::SeqCst);
    let passed = CRYPTO_STATE.tests_passed.load(Ordering::SeqCst);
    if failed > 0 && passed > 0 {
        CertificationStatus::Degraded
    } else if failed > 0 {
        CertificationStatus::Failed
    } else {
        CertificationStatus::Certified
    }
}
