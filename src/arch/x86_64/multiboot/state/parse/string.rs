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

extern crate alloc;

use alloc::string::String;
use core::slice;

use crate::arch::x86_64::multiboot::state::types::MultibootManager;

impl MultibootManager {
    pub(in crate::arch::x86_64::multiboot::state) unsafe fn parse_string_tag(
        &self,
        tag_ptr: *const u8,
        size: u32,
    ) -> Option<String> {
        // SAFETY: Caller guarantees tag_ptr points to valid tag data.
        unsafe {
            if size <= 8 {
                return None;
            }

            let string_ptr = tag_ptr.add(8);
            let max_len = (size - 8) as usize;
            let mut len = 0;

            while len < max_len {
                if *string_ptr.add(len) == 0 {
                    break;
                }
                len += 1;
            }

            if len == 0 {
                return None;
            }

            let slice = slice::from_raw_parts(string_ptr, len);
            core::str::from_utf8(slice).ok().map(String::from)
        }
    }
}
