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
use x86_64::PhysAddr;

use crate::arch::x86_64::multiboot::error::MultibootError;
use crate::arch::x86_64::multiboot::modules::ModuleInfo;
use crate::arch::x86_64::multiboot::state::types::MultibootManager;

impl MultibootManager {
    pub(in crate::arch::x86_64::multiboot::state) unsafe fn parse_module(
        &self,
        tag_ptr: *const u8,
        size: u32,
    ) -> Result<ModuleInfo, MultibootError> {
        // SAFETY: Caller guarantees tag_ptr points to valid module tag.
        unsafe {
            #[repr(C)]
            struct ModuleTag {
                tag_type: u32,
                size: u32,
                mod_start: u32,
                mod_end: u32,
            }

            let tag = &*(tag_ptr as *const ModuleTag);

            if tag.mod_end < tag.mod_start {
                return Err(MultibootError::ModuleError {
                    reason: "Invalid module bounds",
                });
            }

            let cmdline = if size > 16 {
                let cmdline_ptr = tag_ptr.add(16);
                let max_len = (size - 16) as usize;
                let mut len = 0;
                while len < max_len && *cmdline_ptr.add(len) != 0 {
                    len += 1;
                }
                if len > 0 {
                    let slice = slice::from_raw_parts(cmdline_ptr, len);
                    core::str::from_utf8(slice).ok().map(String::from)
                } else {
                    None
                }
            } else {
                None
            };

            Ok(ModuleInfo {
                start: PhysAddr::new(tag.mod_start as u64),
                end: PhysAddr::new(tag.mod_end as u64),
                cmdline,
            })
        }
    }
}
