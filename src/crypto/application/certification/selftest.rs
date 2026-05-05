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

use core::sync::atomic::Ordering;

use super::{
    kat_blake3, kat_chacha20poly1305, kat_ed25519, kat_ntru, kat_rng, kat_sha3_256, kat_sphincs,
    AlgorithmStatus, CRYPTO_STATE,
};
use crate::sys::serial;

fn line(msg: &str) {
    serial::print_str(msg);
    serial::print(b"\r\n");
}

pub fn run_all_selftests() -> bool {
    line("");
    line("NONOS CRYPTOGRAPHIC MODULE SELF-TEST (FIPS 140-3 style)");

    let mut all_passed = true;

    let sha3_status = kat_sha3_256();
    line(&alloc::format!("  SHA3-256                  [{}]", status_str(sha3_status)));
    if sha3_status != AlgorithmStatus::Pass {
        all_passed = false;
    }

    let blake3_status = kat_blake3();
    line(&alloc::format!("  BLAKE3                    [{}]", status_str(blake3_status)));
    if blake3_status != AlgorithmStatus::Pass {
        all_passed = false;
    }

    let chacha_status = kat_chacha20poly1305();
    line(&alloc::format!("  ChaCha20-Poly1305         [{}]", status_str(chacha_status)));
    if chacha_status != AlgorithmStatus::Pass {
        all_passed = false;
    }

    let ed25519_status = kat_ed25519();
    line(&alloc::format!("  Ed25519                   [{}]", status_str(ed25519_status)));
    if ed25519_status != AlgorithmStatus::Pass {
        all_passed = false;
    }

    let rng_status = kat_rng();
    line(&alloc::format!("  RNG health check          [{}]", status_str(rng_status)));
    if rng_status != AlgorithmStatus::Pass {
        all_passed = false;
    }

    let sphincs_status = kat_sphincs();
    line(&alloc::format!("  SPHINCS+ (SLH-DSA)        [{}]", status_str(sphincs_status)));
    if sphincs_status == AlgorithmStatus::Fail {
        all_passed = false;
    }

    let ntru_status = kat_ntru();
    line(&alloc::format!("  NTRU (lattice KEM)        [{}]", status_str(ntru_status)));
    if ntru_status == AlgorithmStatus::Fail {
        all_passed = false;
    }

    CRYPTO_STATE.overall_tests_run.store(true, Ordering::SeqCst);

    let passed = CRYPTO_STATE.tests_passed.load(Ordering::SeqCst);
    let failed = CRYPTO_STATE.tests_failed.load(Ordering::SeqCst);
    line(&alloc::format!("  Summary: {} passed, {} failed", passed, failed));

    if all_passed {
        line("  CRYPTO MODULE SELF-TEST: PASSED");
    } else {
        line("  CRYPTO MODULE SELF-TEST: DEGRADED");
    }

    all_passed
}

fn status_str(status: AlgorithmStatus) -> &'static str {
    match status {
        AlgorithmStatus::Pass => "PASS",
        AlgorithmStatus::Fail => "FAIL",
        AlgorithmStatus::Pending => "PENDING",
        AlgorithmStatus::Unavailable => "N/A",
    }
}
