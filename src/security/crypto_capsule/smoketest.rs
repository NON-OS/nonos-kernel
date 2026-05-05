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

//! Boot-time smoketest for the crypto capsule hash surface. Drives
//! BLAKE3 / SHA3-256 / SHA-256 / SHA-512 against fixed Known-Answer
//! Test (KAT) vectors over the kernel-side client and emits the
//! deterministic marker set greppable by
//! `tests/boot/crypto_hash_round_trip.sh`. Gated on
//! `nonos-crypto-hash-smoketest`; the path is empty in production
//! builds.

use crate::services::lifecycle::smoketest_log;

use super::client;
use super::error::CryptoCapsuleError;
use super::state;

const TAG: &[u8] = b"[CRYPTO-HASH-TEST] ";

// "abc" KAT vectors (RFC 6234 / RustCrypto test vectors / BLAKE3 spec).
const INPUT_ABC: &[u8] = b"abc";

const KAT_BLAKE3_ABC: [u8; 32] = [
    0x64, 0x37, 0xb3, 0xac, 0x38, 0x46, 0x51, 0x33, 0xff, 0xb6, 0x3b, 0x75, 0x27, 0x3a, 0x8d, 0xb5,
    0x48, 0xc5, 0x58, 0x46, 0x5d, 0x79, 0xdb, 0x03, 0xfd, 0x35, 0x9c, 0x6c, 0xd5, 0xbd, 0x9d, 0x85,
];

const KAT_SHA3_256_ABC: [u8; 32] = [
    0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
    0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
];

const KAT_SHA256_ABC: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];

const KAT_SHA512_ABC: [u8; 64] = [
    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
    0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
    0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
    0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
];

pub fn run() {
    if !state::is_alive() {
        return fail_msg(b"capsule not alive");
    }

    match client::hash_blake3(INPUT_ABC) {
        Ok(d) if d == KAT_BLAKE3_ABC => mark(b"blake3 ok"),
        Ok(_) => return fail_msg(b"blake3: digest mismatch"),
        Err(e) => return fail(b"blake3", e),
    }

    match client::hash_sha3_256(INPUT_ABC) {
        Ok(d) if d == KAT_SHA3_256_ABC => mark(b"sha3 ok"),
        Ok(_) => return fail_msg(b"sha3: digest mismatch"),
        Err(e) => return fail(b"sha3", e),
    }

    match client::hash_sha256(INPUT_ABC) {
        Ok(d) if d == KAT_SHA256_ABC => mark(b"sha256 ok"),
        Ok(_) => return fail_msg(b"sha256: digest mismatch"),
        Err(e) => return fail(b"sha256", e),
    }

    match client::hash_sha512(INPUT_ABC) {
        Ok(d) if d == KAT_SHA512_ABC => mark(b"sha512 ok"),
        Ok(_) => return fail_msg(b"sha512: digest mismatch"),
        Err(e) => return fail(b"sha512", e),
    }

    mark(b"PASS");
}

fn mark(stage: &[u8]) {
    smoketest_log::mark(TAG, stage);
}

fn fail(stage: &[u8], err: CryptoCapsuleError) {
    smoketest_log::fail_with_err(TAG, stage, err_name(err));
}

fn fail_msg(reason: &[u8]) {
    smoketest_log::fail_msg(TAG, reason);
}

fn err_name(e: CryptoCapsuleError) -> &'static [u8] {
    match e {
        CryptoCapsuleError::Dead => b"Dead",
        CryptoCapsuleError::Stale => b"Stale",
        CryptoCapsuleError::AccessDenied => b"AccessDenied",
        CryptoCapsuleError::InvalidArgument => b"InvalidArgument",
        CryptoCapsuleError::AuthFailure => b"AuthFailure",
        CryptoCapsuleError::OversizedRequest => b"OversizedRequest",
        CryptoCapsuleError::NoCallerPid => b"NoCallerPid",
        CryptoCapsuleError::TransportFailure => b"TransportFailure",
        CryptoCapsuleError::ProtocolMismatch => b"ProtocolMismatch",
    }
}
