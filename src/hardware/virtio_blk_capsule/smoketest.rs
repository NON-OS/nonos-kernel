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

//! Boot-time runtime proof for the virtio-blk driver capsule.
//! Drives healthcheck, capacity, a one-sector read, a write/read
//! round trip with a deterministic pattern, and a flush. Emits
//! the marker set `tests/boot/virtio_blk_round_trip.sh` greps
//! for. Gated on `nonos-driver-virtio-blk-smoketest`.

use alloc::vec;

use crate::services::lifecycle::smoketest_log;

use super::client;
use super::error::DriverBlkError;
use super::state;

const TAG: &[u8] = b"[DRIVER-BLK-TEST] ";
const SECTOR_SIZE: usize = 512;
const SCRATCH_LBA: u64 = 64;

pub fn run() {
    if !state::is_alive() {
        return fail_msg(b"capsule not alive");
    }
    mark(b"capsule alive");

    if let Err(e) = client::healthcheck() {
        return fail(b"healthcheck", e);
    }
    mark(b"healthcheck ok");

    let cap = match client::capacity() {
        Ok(c) => c,
        Err(e) => return fail(b"capacity", e),
    };
    if cap == 0 {
        return fail_msg(b"capacity returned zero");
    }
    if SCRATCH_LBA + 1 > cap {
        return fail_msg(b"capacity below scratch lba");
    }
    mark(b"capacity ok");

    let mut block0 = vec![0u8; SECTOR_SIZE];
    if let Err(e) = client::read_blocks(0, &mut block0) {
        return fail(b"read block 0", e);
    }
    mark(b"read block 0 ok");

    let mut pattern = vec![0u8; SECTOR_SIZE];
    for (i, b) in pattern.iter_mut().enumerate() {
        *b = ((i as u32).wrapping_mul(0x9E37_79B1) >> 24) as u8;
    }
    if let Err(e) = client::write_blocks(SCRATCH_LBA, &pattern) {
        return fail(b"write scratch", e);
    }
    let mut readback = vec![0u8; SECTOR_SIZE];
    if let Err(e) = client::read_blocks(SCRATCH_LBA, &mut readback) {
        return fail(b"readback scratch", e);
    }
    if readback != pattern {
        return fail_msg(b"write/read round trip: data mismatch");
    }
    mark(b"write/read round trip ok");

    match client::flush() {
        Ok(()) => mark(b"flush ok"),
        Err(DriverBlkError::Unsupported) | Err(DriverBlkError::InvalidArgument) => {
            // Device may not advertise VIRTIO_BLK_F_FLUSH; that
            // is a deterministic refusal, not a failure of the
            // pipeline. Log it and continue.
            mark(b"flush unsupported (device)")
        }
        Err(e) => return fail(b"flush", e),
    }

    mark(b"PASS");
}

fn mark(stage: &[u8]) {
    smoketest_log::mark(TAG, stage);
}

fn fail(stage: &[u8], err: DriverBlkError) {
    smoketest_log::fail_with_err(TAG, stage, err_name(err));
}

fn fail_msg(reason: &[u8]) {
    smoketest_log::fail_msg(TAG, reason);
}

fn err_name(e: DriverBlkError) -> &'static [u8] {
    match e {
        DriverBlkError::Dead => b"Dead",
        DriverBlkError::Stale => b"Stale",
        DriverBlkError::AccessDenied => b"AccessDenied",
        DriverBlkError::InvalidArgument => b"InvalidArgument",
        DriverBlkError::OversizedRequest => b"OversizedRequest",
        DriverBlkError::OutOfRange => b"OutOfRange",
        DriverBlkError::DeviceFailure => b"DeviceFailure",
        DriverBlkError::Unsupported => b"Unsupported",
        DriverBlkError::NoCallerPid => b"NoCallerPid",
        DriverBlkError::TransportFailure => b"TransportFailure",
        DriverBlkError::ProtocolMismatch => b"ProtocolMismatch",
    }
}
