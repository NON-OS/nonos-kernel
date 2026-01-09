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

use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use super::CRYPTO_STATE;

#[derive(Debug, Clone)]
pub struct AlgorithmInfo {
    pub name: &'static str,
    pub standard: &'static str,
    pub security_bits: u16,
    pub post_quantum: bool,
    pub fips_approved: bool,
}

pub fn supported_algorithms() -> Vec<AlgorithmInfo> {
    alloc::vec![
        AlgorithmInfo {
            name: "SHA3-256",
            standard: "NIST FIPS 202",
            security_bits: 128,
            post_quantum: true,
            fips_approved: true,
        },
        AlgorithmInfo {
            name: "BLAKE3",
            standard: "BLAKE3 Spec 1.0",
            security_bits: 128,
            post_quantum: true,
            fips_approved: false,
        },
        AlgorithmInfo {
            name: "ChaCha20-Poly1305",
            standard: "RFC 8439",
            security_bits: 256,
            post_quantum: false,
            fips_approved: false,
        },
        AlgorithmInfo {
            name: "Ed25519",
            standard: "RFC 8032",
            security_bits: 128,
            post_quantum: false,
            fips_approved: false,
        },
        AlgorithmInfo {
            name: "SPHINCS+",
            standard: "NIST FIPS 205 (SLH-DSA)",
            security_bits: 128,
            post_quantum: true,
            fips_approved: true,
        },
        AlgorithmInfo {
            name: "NTRU",
            standard: "NIST PQC Round 3",
            security_bits: 192,
            post_quantum: true,
            fips_approved: false,
        },
    ]
}

pub fn fips_compliance_check() -> bool {
    CRYPTO_STATE.sha3_256.load(Ordering::SeqCst)
    && CRYPTO_STATE.sphincs.load(Ordering::SeqCst)
}

pub fn post_quantum_ready() -> bool {
    CRYPTO_STATE.sphincs.load(Ordering::SeqCst)
    || CRYPTO_STATE.ntru.load(Ordering::SeqCst)
}
