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

#![no_std]
#![no_main]

use nonos_libc::{_exit, mk_debug};

const MSG: &[u8] = b"[proof_io] user mode reached, syscall round trip alive\n";

// ELF entry point. The kernel's loader jumps here after switching to
// CPL=3 with a valid user stack. The binary's only job is to drive
// one observable round trip on the syscall path: emit a marker via
// the NØNOS-native debug channel, then exit. There is no fd, no
// POSIX `write`, and no Linux compatibility behind any of this.
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    let _ = mk_debug(MSG.as_ptr(), MSG.len());
    _exit(0)
}
