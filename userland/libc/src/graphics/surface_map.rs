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

use crate::syscall::{call_raw, N_GFX_SURFACE_MAP};

#[no_mangle]
pub extern "C" fn nonos_surface_map(id: u64) -> *mut u8 {
    let r = call_raw(N_GFX_SURFACE_MAP, [id, 0, 0, 0, 0, 0]);
    if r < 0 {
        return core::ptr::null_mut();
    }
    r as usize as *mut u8
}
