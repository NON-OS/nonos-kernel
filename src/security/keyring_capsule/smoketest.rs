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

//! Boot-time smoketest for the keyring capsule. Drives every op the
//! kernel-side client exposes, asserts the documented errno mapping
//! on the deny paths, and emits the deterministic marker set the
//! `tests/boot/keyring_round_trip.sh` harness greps for.
//!
//! Gated on the `nonos-keyring-smoketest` Cargo feature so the path
//! is empty in production builds. Invoked from
//! `crate::userspace::init::run_init` after `spawn_keyring_capsule`.

use crate::sys::serial;

use super::client;
use super::error::KeyringCapsuleError;
use super::types::KeyType;

const TAG: &[u8] = b"[KEYRING-TEST] ";
const TEST_DATA: &[u8] = b"keyring smoketest payload bytes";

pub fn run() {
    mark(b"capsule alive");

    let id = match client::store(KeyType::Symmetric, TEST_DATA, 0) {
        Ok(id) => {
            mark(b"store ok");
            id
        }
        Err(e) => return fail(b"store", e),
    };

    match client::retrieve(id) {
        Ok(bytes) if bytes == TEST_DATA => mark(b"retrieve ok"),
        Ok(_) => return fail_msg(b"retrieve: byte mismatch"),
        Err(e) => return fail(b"retrieve", e),
    }

    match client::lock(id) {
        Ok(()) => mark(b"lock ok"),
        Err(e) => return fail(b"lock", e),
    }

    match client::retrieve(id) {
        Err(KeyringCapsuleError::Locked) => mark(b"retrieve-locked denied"),
        Ok(_) => return fail_msg(b"retrieve-locked: must EBUSY"),
        Err(e) => return fail(b"retrieve-locked", e),
    }

    match client::unlock(id) {
        Ok(()) => mark(b"unlock ok"),
        Err(e) => return fail(b"unlock", e),
    }

    match client::retrieve(id) {
        Ok(bytes) if bytes == TEST_DATA => mark(b"retrieve-unlocked ok"),
        Ok(_) => return fail_msg(b"retrieve-unlocked: byte mismatch"),
        Err(e) => return fail(b"retrieve-unlocked", e),
    }

    match client::metadata(id) {
        Ok(m) if m.id == id
            && m.size as usize == TEST_DATA.len()
            && !m.locked
            && m.use_count >= 2 =>
        {
            mark(b"metadata ok")
        }
        Ok(_) => return fail_msg(b"metadata: field mismatch"),
        Err(e) => return fail(b"metadata", e),
    }

    match client::count() {
        Ok(n) if n >= 1 => mark(b"count ok"),
        Ok(_) => return fail_msg(b"count: expected >= 1"),
        Err(e) => return fail(b"count", e),
    }

    match client::delete(id) {
        Ok(()) => mark(b"delete ok"),
        Err(e) => return fail(b"delete", e),
    }

    match client::retrieve(id) {
        Err(KeyringCapsuleError::NotFound) => mark(b"retrieve-after-delete denied"),
        Ok(_) => return fail_msg(b"retrieve-after-delete: must ENOENT"),
        Err(e) => return fail(b"retrieve-after-delete", e),
    }

    mark(b"PASS");
}

fn mark(stage: &[u8]) {
    let mut buf = [0u8; 128];
    let mut n = 0;
    for &b in TAG {
        if n < buf.len() {
            buf[n] = b;
            n += 1;
        }
    }
    for &b in stage {
        if n < buf.len() {
            buf[n] = b;
            n += 1;
        }
    }
    serial::println(&buf[..n]);
}

fn fail(stage: &[u8], err: KeyringCapsuleError) {
    let mut msg = [0u8; 96];
    let mut n = 0;
    for &b in b"FAIL: " {
        if n < msg.len() {
            msg[n] = b;
            n += 1;
        }
    }
    for &b in stage {
        if n < msg.len() {
            msg[n] = b;
            n += 1;
        }
    }
    for &b in b" -> " {
        if n < msg.len() {
            msg[n] = b;
            n += 1;
        }
    }
    for &b in err_name(err) {
        if n < msg.len() {
            msg[n] = b;
            n += 1;
        }
    }
    mark(&msg[..n]);
}

fn fail_msg(reason: &[u8]) {
    let mut msg = [0u8; 96];
    let mut n = 0;
    for &b in b"FAIL: " {
        if n < msg.len() {
            msg[n] = b;
            n += 1;
        }
    }
    for &b in reason {
        if n < msg.len() {
            msg[n] = b;
            n += 1;
        }
    }
    mark(&msg[..n]);
}

fn err_name(e: KeyringCapsuleError) -> &'static [u8] {
    match e {
        KeyringCapsuleError::Dead => b"Dead",
        KeyringCapsuleError::Stale => b"Stale",
        KeyringCapsuleError::AccessDenied => b"AccessDenied",
        KeyringCapsuleError::NotFound => b"NotFound",
        KeyringCapsuleError::Locked => b"Locked",
        KeyringCapsuleError::Full => b"Full",
        KeyringCapsuleError::InvalidArgument => b"InvalidArgument",
        KeyringCapsuleError::NoCallerPid => b"NoCallerPid",
        KeyringCapsuleError::TransportFailure => b"TransportFailure",
        KeyringCapsuleError::ProtocolMismatch => b"ProtocolMismatch",
    }
}
