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

//! Thin serial-log helpers. The capsule writes phase markers to fd
//! 1 (stdout); the boot harness greps for them.

use nonos_libc::write;

pub fn line(msg: &str) {
    let bytes = msg.as_bytes();
    let _ = write(1, bytes.as_ptr(), bytes.len());
    let _ = write(1, b"\n".as_ptr(), 1);
}

pub fn marker(stage: &str) {
    let prefix = b"[driver_rng] ";
    let rest = stage.as_bytes();
    let _ = write(1, prefix.as_ptr(), prefix.len());
    let _ = write(1, rest.as_ptr(), rest.len());
    let _ = write(1, b"\n".as_ptr(), 1);
}
