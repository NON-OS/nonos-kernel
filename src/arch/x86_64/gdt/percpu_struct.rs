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

use crate::arch::x86_64::gdt::constants::*;
use crate::arch::x86_64::gdt::table::Gdt;
use crate::arch::x86_64::gdt::tss::Tss;

// PerCpuGdt owns the GDT, the TSS, and one stack per architectural
// fault delivery class plus the per-CPU kernel stack used as TSS.RSP0
// for CPL=3 → CPL=0 traps. There is one stack for each of the seven
// IST slots (1..7); a CPU exception that uses an IST index must find
// a non-zero stack pointer in TSS.IST[i] or the CPU triple-faults
// before any handler runs. Whenever a new IDT entry calls
// `set_stack_index(N)`, the matching IST slot in `init` must already
// be set or the static gate over this file fails closed.
#[repr(C, align(64))]
pub struct PerCpuGdt {
    pub gdt: Gdt,
    pub tss: Tss,
    pub ist1_stack: [u8; DEFAULT_STACK_SIZE],
    pub ist2_stack: [u8; DEFAULT_STACK_SIZE],
    pub ist3_stack: [u8; DEFAULT_STACK_SIZE],
    pub ist4_stack: [u8; DEFAULT_STACK_SIZE],
    pub ist5_stack: [u8; DEFAULT_STACK_SIZE],
    pub ist6_stack: [u8; DEFAULT_STACK_SIZE],
    pub ist7_stack: [u8; DEFAULT_STACK_SIZE],
    pub kernel_stack: [u8; DEFAULT_STACK_SIZE],
    pub cpu_id: u32,
    pub initialized: bool,
}

impl PerCpuGdt {
    pub const fn new() -> Self {
        Self {
            gdt: Gdt::new(),
            tss: Tss::new(),
            ist1_stack: [0; DEFAULT_STACK_SIZE],
            ist2_stack: [0; DEFAULT_STACK_SIZE],
            ist3_stack: [0; DEFAULT_STACK_SIZE],
            ist4_stack: [0; DEFAULT_STACK_SIZE],
            ist5_stack: [0; DEFAULT_STACK_SIZE],
            ist6_stack: [0; DEFAULT_STACK_SIZE],
            ist7_stack: [0; DEFAULT_STACK_SIZE],
            kernel_stack: [0; DEFAULT_STACK_SIZE],
            cpu_id: 0,
            initialized: false,
        }
    }

    pub fn init(&mut self, cpu_id: u32) {
        self.cpu_id = cpu_id;
        let ist1_top = self.ist1_stack.as_ptr() as u64 + DEFAULT_STACK_SIZE as u64;
        let ist2_top = self.ist2_stack.as_ptr() as u64 + DEFAULT_STACK_SIZE as u64;
        let ist3_top = self.ist3_stack.as_ptr() as u64 + DEFAULT_STACK_SIZE as u64;
        let ist4_top = self.ist4_stack.as_ptr() as u64 + DEFAULT_STACK_SIZE as u64;
        let ist5_top = self.ist5_stack.as_ptr() as u64 + DEFAULT_STACK_SIZE as u64;
        let ist6_top = self.ist6_stack.as_ptr() as u64 + DEFAULT_STACK_SIZE as u64;
        let ist7_top = self.ist7_stack.as_ptr() as u64 + DEFAULT_STACK_SIZE as u64;
        let kernel_top = self.kernel_stack.as_ptr() as u64 + DEFAULT_STACK_SIZE as u64;
        let _ = self.tss.set_ist(IST_DOUBLE_FAULT, ist1_top);
        let _ = self.tss.set_ist(IST_NMI, ist2_top);
        let _ = self.tss.set_ist(IST_MACHINE_CHECK, ist3_top);
        let _ = self.tss.set_ist(IST_DEBUG, ist4_top);
        let _ = self.tss.set_ist(IST_PAGE_FAULT, ist5_top);
        let _ = self.tss.set_ist(IST_GP, ist6_top);
        let _ = self.tss.set_ist(IST_RESERVED, ist7_top);
        self.tss.set_rsp0(kernel_top);
        let tss_addr = &self.tss as *const Tss as u64;
        self.gdt.set_tss(tss_addr);
        self.initialized = true;
    }
}
