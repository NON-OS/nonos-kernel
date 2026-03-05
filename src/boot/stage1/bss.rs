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

/// # Safety
///
/// Must be called once at boot before using static variables.
pub unsafe fn clear_bss() {
    // SAFETY: Linker-provided symbols for BSS section bounds
    extern "C" {
        static __bss_start: u8;
        static __bss_end: u8;
    }

    // SAFETY: These are linker-provided addresses, not actual values
    // Using addr_of! to avoid creating references to linker symbols
    unsafe {
        let start = core::ptr::addr_of!(__bss_start) as usize;
        let end = core::ptr::addr_of!(__bss_end) as usize;
        let len = end.saturating_sub(start);

        if len > 0 {
            // SAFETY: BSS section is valid writable memory, caller guarantees single call
            core::ptr::write_bytes(start as *mut u8, 0, len);
        }
    }
}
