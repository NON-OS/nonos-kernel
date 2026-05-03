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

use crate::syscall::{call_raw, N_GFX_SURFACE_PRESENT_RECT};

#[no_mangle]
pub extern "C" fn nonos_surface_present_rect(
    display: u32,
    id: u64,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
) -> i64 {
    call_raw(
        N_GFX_SURFACE_PRESENT_RECT,
        [display as u64, id, x as u64, y as u64, w as u64, h as u64],
    )
}
