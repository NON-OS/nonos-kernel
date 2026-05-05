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

//! Boot-time smoketest for the VFS capsule. Drives every kernel-side
//! client op against the in-memory store and emits the deterministic
//! marker set greppable by `tests/boot/vfs_round_trip.sh`. Gated on
//! `nonos-vfs-smoketest`; the path is empty in production builds.

use crate::services::lifecycle::smoketest_log;

use super::client;
use super::client::OpenFlags;
use super::error::VfsCapsuleError;
use super::state;

const TAG: &[u8] = b"[VFS-TEST] ";
const PATH: &str = "/test/smoke.bin";
const PAYLOAD: &[u8] = b"vfs smoketest payload bytes";

pub fn run() {
    if !state::is_alive() {
        return fail_msg(b"capsule not alive");
    }

    let create = OpenFlags { create: true, truncate: true, append: false };
    let fd = match client::open(PATH, create) {
        Ok(fd) => {
            mark(b"open ok");
            fd
        }
        Err(e) => return fail(b"open", e),
    };

    match client::write(fd, PAYLOAD) {
        Ok(n) if n as usize == PAYLOAD.len() => mark(b"write ok"),
        Ok(_) => return fail_msg(b"write: short count"),
        Err(e) => return fail(b"write", e),
    }

    if let Err(e) = client::close(fd) {
        return fail(b"close-after-write", e);
    }

    let fd = match client::open(PATH, OpenFlags::default()) {
        Ok(fd) => fd,
        Err(e) => return fail(b"reopen", e),
    };

    match client::read(fd, PAYLOAD.len() + 16) {
        Ok(buf) if buf == PAYLOAD => mark(b"read ok"),
        Ok(_) => return fail_msg(b"read: byte mismatch"),
        Err(e) => return fail(b"read", e),
    }

    match client::stat(PATH) {
        Ok(info) if info.size as usize == PAYLOAD.len() => mark(b"stat ok"),
        Ok(_) => return fail_msg(b"stat: size mismatch"),
        Err(e) => return fail(b"stat", e),
    }

    match client::list("/test/") {
        Ok(entries) if entries.iter().any(|p| p == PATH) => mark(b"list ok"),
        Ok(_) => return fail_msg(b"list: path missing"),
        Err(e) => return fail(b"list", e),
    }

    match client::close(fd) {
        Ok(()) => mark(b"close ok"),
        Err(e) => return fail(b"close", e),
    }

    mark(b"PASS");
}

fn mark(stage: &[u8]) {
    smoketest_log::mark(TAG, stage);
}

fn fail(stage: &[u8], err: VfsCapsuleError) {
    smoketest_log::fail_with_err(TAG, stage, err_name(err));
}

fn fail_msg(reason: &[u8]) {
    smoketest_log::fail_msg(TAG, reason);
}

fn err_name(e: VfsCapsuleError) -> &'static [u8] {
    match e {
        VfsCapsuleError::Dead => b"Dead",
        VfsCapsuleError::Stale => b"Stale",
        VfsCapsuleError::AccessDenied => b"AccessDenied",
        VfsCapsuleError::NotFound => b"NotFound",
        VfsCapsuleError::BadFd => b"BadFd",
        VfsCapsuleError::Full => b"Full",
        VfsCapsuleError::InvalidArgument => b"InvalidArgument",
        VfsCapsuleError::OversizedRequest => b"OversizedRequest",
        VfsCapsuleError::NoCallerPid => b"NoCallerPid",
        VfsCapsuleError::TransportFailure => b"TransportFailure",
        VfsCapsuleError::ProtocolMismatch => b"ProtocolMismatch",
    }
}
