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

//! Bring-up markers for the PS/2 input capsule. The boot smoke
//! harness greps for these exact strings; emitting them through the
//! NØNOS-native MkDebug channel keeps the diagnostics auditable and
//! removes any dependency on a POSIX `write` shim.

use nonos_libc::mk_debug;

const PREFIX: &[u8] = b"[driver_ps2] ";
const NEWLINE: &[u8] = b"\n";
const MAX_LABEL: usize = 200;

pub fn marker(label: &[u8]) {
    let label_len = if label.len() > MAX_LABEL { MAX_LABEL } else { label.len() };
    let total = PREFIX.len() + label_len + NEWLINE.len();
    let mut buf = [0u8; PREFIX.len() + MAX_LABEL + 1];
    let prefix_end = PREFIX.len();
    buf[..prefix_end].copy_from_slice(PREFIX);
    buf[prefix_end..prefix_end + label_len].copy_from_slice(&label[..label_len]);
    buf[prefix_end + label_len] = b'\n';
    let _ = mk_debug(buf.as_ptr(), total);
}
