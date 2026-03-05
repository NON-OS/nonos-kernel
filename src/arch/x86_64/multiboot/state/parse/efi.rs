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

use x86_64::PhysAddr;

use crate::arch::x86_64::multiboot::state::types::MultibootManager;

impl MultibootManager {
    pub(in crate::arch::x86_64::multiboot::state) unsafe fn parse_efi32_ptr(
        &self,
        tag_ptr: *const u8,
    ) -> Option<u32> {
        // SAFETY: Caller guarantees tag_ptr points to valid EFI32 pointer tag.
        unsafe {
            let ptr = *(tag_ptr.add(8) as *const u32);
            if ptr != 0 {
                Some(ptr)
            } else {
                None
            }
        }
    }

    pub(in crate::arch::x86_64::multiboot::state) unsafe fn parse_efi64_ptr(
        &self,
        tag_ptr: *const u8,
    ) -> Option<u64> {
        // SAFETY: Caller guarantees tag_ptr points to valid EFI64 pointer tag.
        unsafe {
            let ptr = *(tag_ptr.add(8) as *const u64);
            if ptr != 0 {
                Some(ptr)
            } else {
                None
            }
        }
    }

    pub(in crate::arch::x86_64::multiboot::state) unsafe fn parse_image_load_base(
        &self,
        tag_ptr: *const u8,
    ) -> Option<PhysAddr> {
        // SAFETY: Caller guarantees tag_ptr points to valid image load base tag.
        unsafe {
            let addr = *(tag_ptr.add(8) as *const u32);
            Some(PhysAddr::new(addr as u64))
        }
    }
}
