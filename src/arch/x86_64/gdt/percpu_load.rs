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

use super::percpu_struct::PerCpuGdt;
use crate::arch::x86_64::gdt::constants::SEL_TSS;
use crate::arch::x86_64::gdt::error::GdtError;
use crate::arch::x86_64::gdt::segments::reload_segments_internal;
use crate::arch::x86_64::gdt::table::GdtPtr;
use core::arch::asm;

impl PerCpuGdt {
    pub unsafe fn load(&self) -> Result<(), GdtError> {
        unsafe {
            if !self.initialized {
                return Err(GdtError::NotInitialized);
            }
            let gdt_ptr = GdtPtr::from_gdt(&self.gdt);
            asm!("lgdt [{}]", in(reg) &gdt_ptr, options(readonly, nostack, preserves_flags));
            reload_segments_internal();
            asm!("ltr {:x}", in(reg) SEL_TSS, options(nomem, nostack, preserves_flags));
            Ok(())
        }
    }
}
