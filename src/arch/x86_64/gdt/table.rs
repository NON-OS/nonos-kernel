// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use core::mem::size_of;
use crate::arch::x86_64::gdt::constants::TSS_SIZE;
use crate::arch::x86_64::gdt::entry::GdtEntry;
use crate::arch::x86_64::gdt::tss::TssEntry;

#[repr(C, packed)]
pub struct Gdt {
    pub null: GdtEntry,
    pub kernel_code: GdtEntry,
    pub kernel_data: GdtEntry,
    pub user_data: GdtEntry,
    pub user_code: GdtEntry,
    pub tss: TssEntry,
}

impl Gdt {
    pub const fn new() -> Self {
        Self {
            null: GdtEntry::null(),
            kernel_code: GdtEntry::kernel_code_64(),
            kernel_data: GdtEntry::kernel_data(),
            user_data: GdtEntry::user_data(),
            user_code: GdtEntry::user_code_64(),
            tss: TssEntry::empty(),
        }
    }

    pub fn set_tss(&mut self, tss_addr: u64) {
        self.tss = TssEntry::new(tss_addr, (TSS_SIZE - 1) as u32);
    }

    pub const fn size() -> usize {
        size_of::<Self>()
    }
}

#[repr(C, packed)]
pub struct GdtPtr {
    pub limit: u16,
    pub base: u64,
}

impl GdtPtr {
    pub fn from_gdt(gdt: &Gdt) -> Self {
        Self {
            limit: (Gdt::size() - 1) as u16,
            base: gdt as *const Gdt as u64,
        }
    }
}
