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

//! Boot-time runtime proof for the virtio-rng driver capsule.
//! Drives healthcheck, three fills (32 / 256 / 4096 bytes) and one
//! oversize fill that must come back as `OversizedRequest`. Emits
//! the marker set `tests/boot/virtio_rng_round_trip.sh` greps for.
//! Gated on `nonos-driver-virtio-rng-smoketest`.

use crate::services::lifecycle::smoketest_log;

use super::client;
use super::error::DriverRngError;
use super::state;

const TAG: &[u8] = b"[DRIVER-RNG-TEST] ";

pub fn run() {
    if !state::is_alive() {
        return fail_msg(b"capsule not alive");
    }
    mark(b"capsule alive");

    if let Err(e) = client::healthcheck() {
        return fail(b"healthcheck", e);
    }
    mark(b"healthcheck ok");

    let mut buf32 = [0u8; 32];
    if let Err(e) = client::fill_random(&mut buf32) {
        return fail(b"fill 32B", e);
    }
    if all_zero(&buf32) {
        return fail_msg(b"fill 32B: all zero");
    }
    mark(b"fill 32 ok");

    let mut buf256 = [0u8; 256];
    if let Err(e) = client::fill_random(&mut buf256) {
        return fail(b"fill 256B", e);
    }
    if all_zero(&buf256) {
        return fail_msg(b"fill 256B: all zero");
    }
    if buf256[..32] == buf32[..] {
        return fail_msg(b"fill 256B: prefix matches prior fill");
    }
    mark(b"fill 256 ok");

    let mut bufmax = [0u8; 4096];
    if let Err(e) = client::fill_random(&mut bufmax) {
        return fail(b"fill max", e);
    }
    if all_zero(&bufmax) {
        return fail_msg(b"fill max: all zero");
    }
    mark(b"fill max ok");

    let mut huge = [0u8; 8192];
    match client::fill_random(&mut huge) {
        Err(DriverRngError::OversizedRequest) => mark(b"oversized denied"),
        Ok(_) => return fail_msg(b"oversized: must be denied"),
        Err(e) => return fail(b"oversized", e),
    }

    mark(b"PASS");
}

fn all_zero(buf: &[u8]) -> bool {
    buf.iter().all(|&b| b == 0)
}

fn mark(stage: &[u8]) {
    smoketest_log::mark(TAG, stage);
}

fn fail(stage: &[u8], err: DriverRngError) {
    smoketest_log::fail_with_err(TAG, stage, err_name(err));
}

fn fail_msg(reason: &[u8]) {
    smoketest_log::fail_msg(TAG, reason);
}

fn err_name(e: DriverRngError) -> &'static [u8] {
    match e {
        DriverRngError::Dead => b"Dead",
        DriverRngError::Stale => b"Stale",
        DriverRngError::AccessDenied => b"AccessDenied",
        DriverRngError::OversizedRequest => b"OversizedRequest",
        DriverRngError::InvalidArgument => b"InvalidArgument",
        DriverRngError::DeviceFailure => b"DeviceFailure",
        DriverRngError::NoCallerPid => b"NoCallerPid",
        DriverRngError::TransportFailure => b"TransportFailure",
        DriverRngError::ProtocolMismatch => b"ProtocolMismatch",
    }
}
