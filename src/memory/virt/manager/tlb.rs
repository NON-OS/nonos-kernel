// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::super::stats::VM_STATS;
use super::core::VirtualMemoryManager;
use x86_64::registers::control::{Cr3, Cr3Flags};
use crate::memory::addr::VirtAddr;

impl VirtualMemoryManager {
    pub fn flush_tlb_single(&self, va: VirtAddr) {
        unsafe {
            core::arch::asm!("invlpg [{}]", in(reg) va.as_u64(), options(nostack, preserves_flags));
        }
        VM_STATS.record_tlb_flush();
    }

    pub fn flush_tlb_all(&self) {
        unsafe {
            let cr3 = Cr3::read().0;
            Cr3::write(cr3, Cr3Flags::empty());
        }
        VM_STATS.record_tlb_flush();
    }
}
