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

//! Boot-time smoketest for the ramfs capsule path. Runs only when the
//! `nonos-ramfs-smoketest` feature is on. Invokes the capsule client
//! directly to drive a full Open/Write/Read/Truncate/Close round trip
//! and emits one marker line per stage on the serial console; the
//! external harness greps for these markers to decide pass or fail.

use super::client;
use crate::fs::fd::O_CREAT;
use crate::sys::serial::println;

const PATH: &str = "/ram/smoketest";
const PAYLOAD: &[u8] = b"NONOS-RAMFS-CAPSULE-RUNTIME-PROOF";

pub fn run() {
    println(b"[RAMFS-TEST] open begin");
    let opened = match client::open(PATH, O_CREAT) {
        Ok(o) => o,
        Err(_) => return println(b"[RAMFS-TEST] FAIL: open"),
    };
    println(b"[RAMFS-TEST] open ok");

    if client::write(opened.remote_handle, opened.generation, 0, PAYLOAD).is_err() {
        return println(b"[RAMFS-TEST] FAIL: write");
    }
    println(b"[RAMFS-TEST] write ok");

    let bytes = match client::read(opened.remote_handle, opened.generation, 0, PAYLOAD.len() as u32)
    {
        Ok(b) => b,
        Err(_) => return println(b"[RAMFS-TEST] FAIL: read"),
    };
    if bytes.as_slice() != PAYLOAD {
        return println(b"[RAMFS-TEST] FAIL: data mismatch");
    }
    println(b"[RAMFS-TEST] read ok");

    if client::truncate(opened.remote_handle, opened.generation, 0).is_err() {
        return println(b"[RAMFS-TEST] FAIL: truncate");
    }
    println(b"[RAMFS-TEST] truncate ok");

    if client::close(opened.remote_handle, opened.generation).is_err() {
        return println(b"[RAMFS-TEST] FAIL: close");
    }
    println(b"[RAMFS-TEST] close ok");

    println(b"[RAMFS-TEST] PASS");
}
