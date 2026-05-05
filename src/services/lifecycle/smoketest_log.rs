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

//! Marker emitter for boot-time capsule smoketests. Each line is a
//! per-capsule tag prefix plus a stage string; the boot-test harness
//! scripts grep for them. Built in a stack buffer so the emitter is
//! no-alloc and re-entry-safe.

use crate::sys::serial;

const LINE_BUDGET: usize = 128;
const FAIL_PREFIX: &[u8] = b"FAIL: ";

pub fn mark(tag: &[u8], stage: &[u8]) {
    let mut buf = [0u8; LINE_BUDGET];
    let mut n = 0;
    n = write_into(&mut buf, n, tag);
    n = write_into(&mut buf, n, stage);
    serial::println(&buf[..n]);
}

pub fn fail_msg(tag: &[u8], reason: &[u8]) {
    let mut buf = [0u8; LINE_BUDGET];
    let mut n = 0;
    n = write_into(&mut buf, n, tag);
    n = write_into(&mut buf, n, FAIL_PREFIX);
    n = write_into(&mut buf, n, reason);
    serial::println(&buf[..n]);
}

pub fn fail_with_err(tag: &[u8], stage: &[u8], err_name: &[u8]) {
    let mut buf = [0u8; LINE_BUDGET];
    let mut n = 0;
    n = write_into(&mut buf, n, tag);
    n = write_into(&mut buf, n, FAIL_PREFIX);
    n = write_into(&mut buf, n, stage);
    n = write_into(&mut buf, n, b" -> ");
    n = write_into(&mut buf, n, err_name);
    serial::println(&buf[..n]);
}

fn write_into(buf: &mut [u8], mut at: usize, src: &[u8]) -> usize {
    for &b in src {
        if at >= buf.len() {
            break;
        }
        buf[at] = b;
        at += 1;
    }
    at
}
