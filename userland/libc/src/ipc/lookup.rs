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

use crate::syscall::{call_raw, N_MK_SERVICE_LOOKUP};

// Look up a service by name. On success the kernel writes the
// registered port into `*port_out` and the owning pid into
// `*pid_out` (each may be null when uninterested). Used by
// capsule setup to resolve peer endpoints without hardcoding
// the wire-side port numbers.
#[no_mangle]
pub extern "C" fn mk_service_lookup(
    name: *const u8,
    name_len: usize,
    port_out: *mut u32,
    pid_out: *mut u32,
) -> i64 {
    call_raw(
        N_MK_SERVICE_LOOKUP,
        [name as u64, name_len as u64, port_out as u64, pid_out as u64, 0, 0],
    )
}
