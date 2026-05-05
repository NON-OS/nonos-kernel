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

//! Boot-time smoketest for the entropy capsule. Drives every kernel-
//! side client op, asserts the documented errno mapping on the deny
//! path, and emits the deterministic marker set greppable by
//! `tests/boot/entropy_round_trip.sh`. Gated on
//! `nonos-entropy-smoketest`; the path is empty in production builds.

use crate::services::lifecycle::smoketest_log;

use super::client;
use super::error::EntropyCapsuleError;
use super::state;

const TAG: &[u8] = b"[ENTROPY-TEST] ";

pub fn run() {
    if !state::is_alive() {
        return fail_msg(b"capsule not alive");
    }
    mark(b"capsule alive");

    let mut buf_a = [0u8; 64];
    match client::get_random(&mut buf_a) {
        Ok(n) if n == buf_a.len() => mark(b"getrandom ok"),
        Ok(_) => return fail_msg(b"getrandom: short read"),
        Err(e) => return fail(b"getrandom", e),
    }

    let mut buf_b = [0u8; 64];
    match client::get_random(&mut buf_b) {
        Ok(n) if n == buf_b.len() => {
            if buf_a == buf_b {
                return fail_msg(b"repeat: identical buffers");
            }
            mark(b"repeat differs");
        }
        Ok(_) => return fail_msg(b"repeat: short read"),
        Err(e) => return fail(b"repeat", e),
    }

    match client::get_stats() {
        Ok(s) if s.uptime_requests >= 2 && s.bytes_served >= 128 => mark(b"stats ok"),
        Ok(_) => return fail_msg(b"stats: counters below expected"),
        Err(e) => return fail(b"stats", e),
    }

    let mut huge = [0u8; 8192];
    match client::get_random(&mut huge) {
        Err(EntropyCapsuleError::OversizedRequest) => mark(b"oversized denied"),
        Ok(_) => return fail_msg(b"oversized: must be denied"),
        Err(e) => return fail(b"oversized", e),
    }

    mark(b"PASS");
}

fn mark(stage: &[u8]) {
    smoketest_log::mark(TAG, stage);
}

fn fail(stage: &[u8], err: EntropyCapsuleError) {
    smoketest_log::fail_with_err(TAG, stage, err_name(err));
}

fn fail_msg(reason: &[u8]) {
    smoketest_log::fail_msg(TAG, reason);
}

fn err_name(e: EntropyCapsuleError) -> &'static [u8] {
    match e {
        EntropyCapsuleError::Dead => b"Dead",
        EntropyCapsuleError::Stale => b"Stale",
        EntropyCapsuleError::AccessDenied => b"AccessDenied",
        EntropyCapsuleError::InvalidArgument => b"InvalidArgument",
        EntropyCapsuleError::OversizedRequest => b"OversizedRequest",
        EntropyCapsuleError::NoCallerPid => b"NoCallerPid",
        EntropyCapsuleError::TransportFailure => b"TransportFailure",
        EntropyCapsuleError::ProtocolMismatch => b"ProtocolMismatch",
        EntropyCapsuleError::SourceFailure => b"SourceFailure",
    }
}
