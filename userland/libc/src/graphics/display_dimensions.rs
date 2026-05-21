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

use crate::syscall::{call_raw, N_GFX_DISPLAY_DIMENSIONS};

#[no_mangle]
pub extern "C" fn nonos_display_dimensions(
    display: u32,
    out_width: *mut u32,
    out_height: *mut u32,
) -> i64 {
    if out_width.is_null() || out_height.is_null() {
        return -22;
    }
    call_raw(
        N_GFX_DISPLAY_DIMENSIONS,
        [display as u64, out_width as u64, out_height as u64, 0, 0, 0],
    )
}
