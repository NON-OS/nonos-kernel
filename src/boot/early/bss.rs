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

pub unsafe fn clear_bss() { unsafe {
    // SAFETY: Must be called exactly once at boot before using any static variables
    extern "C" {
        static mut __bss_start: u8;
        static mut __bss_end: u8;
    }

    let start = &raw const __bss_start as *const u8 as usize;
    let end = &raw const __bss_end as *const u8 as usize;
    let len = end.saturating_sub(start);

    if len > 0 {
        core::ptr::write_bytes(start as *mut u8, 0, len);
    }
}}
