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

use crate::syscall::{call_raw, N_GFX_DISPLAY_LIST};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NonosDisplayInfo {
    pub id: u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub fmt: u32,
    pub flags: u32,
}

#[no_mangle]
pub extern "C" fn nonos_display_list(out_buf: *mut NonosDisplayInfo, max: u32) -> i64 {
    call_raw(N_GFX_DISPLAY_LIST, [out_buf as u64, max as u64, 0, 0, 0, 0])
}
