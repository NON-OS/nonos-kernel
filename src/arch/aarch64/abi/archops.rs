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

use crate::arch::abi::ArchOps;
use crate::memory::addr::{PhysAddr, VirtAddr};

use super::{address_space, cpu_id, halt, irq_disable, irq_enable, irq_state, time, tlb};

pub struct Aarch64;

impl ArchOps for Aarch64 {
    #[inline(always)]
    fn halt() -> ! {
        halt::halt()
    }

    #[inline(always)]
    unsafe fn enable_interrupts() {
        irq_enable::enable()
    }

    #[inline(always)]
    unsafe fn disable_interrupts() {
        irq_disable::disable()
    }

    #[inline(always)]
    fn interrupts_enabled() -> bool {
        irq_state::enabled()
    }

    #[inline(always)]
    fn current_cpu_id() -> u32 {
        cpu_id::current()
    }

    #[inline(always)]
    fn read_time_counter() -> u64 {
        time::counter()
    }

    #[inline(always)]
    unsafe fn flush_tlb_one(addr: VirtAddr) {
        tlb::flush_one(addr)
    }

    #[inline(always)]
    unsafe fn switch_address_space(root: PhysAddr) {
        address_space::switch(root)
    }
}
