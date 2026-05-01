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

use super::core::MMU;
use core::arch::asm;
use crate::memory::addr::VirtAddr;

impl MMU {
    pub fn invalidate_tlb_all(&self) {
        unsafe {
            let cr3: u64;
            asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
            asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
        }
    }

    pub fn invalidate_tlb_page(&self, virt_addr: VirtAddr) {
        unsafe {
            asm!("invlpg [{}]", in(reg) virt_addr.as_u64(), options(nostack, preserves_flags));
        }
    }
}
