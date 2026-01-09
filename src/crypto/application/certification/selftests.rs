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

use core::sync::atomic::Ordering;

use super::{
    AlgorithmStatus, CRYPTO_STATE,
    kat_sha3_256, kat_blake3, kat_chacha20poly1305,
    kat_ed25519, kat_rng, kat_sphincs, kat_ntru,
};

pub fn run_all_selftests() -> bool {
    use crate::drivers::console;

    console::write_message("");
    console::write_message("╔═══════════════════════════════════════════════════════════════════╗");
    console::write_message("║       NØNOS CRYPTOGRAPHIC MODULE SELF-TEST (FIPS 140-3)           ║");
    console::write_message("╚═══════════════════════════════════════════════════════════════════╝");

    let mut all_passed = true;

    let sha3_status = kat_sha3_256();
    console::write_message(&alloc::format!(
        "  SHA3-256 (FIPS 202).............. [{}]",
        status_str(sha3_status)
    ));
    if sha3_status != AlgorithmStatus::Pass { all_passed = false; }

    let blake3_status = kat_blake3();
    console::write_message(&alloc::format!(
        "  BLAKE3..........................  [{}]",
        status_str(blake3_status)
    ));
    if blake3_status != AlgorithmStatus::Pass { all_passed = false; }

    let chacha_status = kat_chacha20poly1305();
    console::write_message(&alloc::format!(
        "  ChaCha20-Poly1305 (RFC 8439)....  [{}]",
        status_str(chacha_status)
    ));
    if chacha_status != AlgorithmStatus::Pass { all_passed = false; }

    let ed25519_status = kat_ed25519();
    console::write_message(&alloc::format!(
        "  Ed25519 (RFC 8032)..............  [{}]",
        status_str(ed25519_status)
    ));
    if ed25519_status != AlgorithmStatus::Pass { all_passed = false; }

    let rng_status = kat_rng();
    console::write_message(&alloc::format!(
        "  RNG Health Check...............   [{}]",
        status_str(rng_status)
    ));
    if rng_status != AlgorithmStatus::Pass { all_passed = false; }

    let sphincs_status = kat_sphincs();
    console::write_message(&alloc::format!(
        "  SPHINCS+ (SLH-DSA PQC).........   [{}]",
        status_str(sphincs_status)
    ));
    if sphincs_status == AlgorithmStatus::Fail { all_passed = false; }

    let ntru_status = kat_ntru();
    console::write_message(&alloc::format!(
        "  NTRU (Lattice KEM PQC).........   [{}]",
        status_str(ntru_status)
    ));
    if ntru_status == AlgorithmStatus::Fail { all_passed = false; }

    CRYPTO_STATE.overall_tests_run.store(true, Ordering::SeqCst);

    let passed = CRYPTO_STATE.tests_passed.load(Ordering::SeqCst);
    let failed = CRYPTO_STATE.tests_failed.load(Ordering::SeqCst);

    console::write_message("");
    console::write_message(&alloc::format!(
        "  Summary: {} passed, {} failed",
        passed, failed
    ));

    if all_passed {
        console::write_message("");
        console::write_message("  ════════════════════════════════════════════════════════════════");
        console::write_message("  CRYPTO MODULE SELF-TEST: PASSED - Certified for use");
        console::write_message("  ════════════════════════════════════════════════════════════════");
    } else {
        console::write_message("");
        console::write_message("  ════════════════════════════════════════════════════════════════");
        console::write_message("  CRYPTO MODULE SELF-TEST: DEGRADED - Some algorithms unavailable");
        console::write_message("  ════════════════════════════════════════════════════════════════");
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
