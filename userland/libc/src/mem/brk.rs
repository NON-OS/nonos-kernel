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

use crate::syscall::{call_raw, N_BRK};

// `brk(0)` returns the current program break; `brk(addr)` sets the
// break and returns the new value (or the old value on failure, per the
// kernel `handle_brk` semantics).
#[no_mangle]
pub extern "C" fn brk(addr: u64) -> u64 {
    call_raw(N_BRK, [addr, 0, 0, 0, 0, 0]) as u64
}
