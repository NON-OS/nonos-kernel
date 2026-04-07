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

use core::arch::asm;

pub fn cpu_yield() { unsafe { asm!("hlt"); } }

pub fn idle_cpu() { unsafe { asm!("sti; hlt", options(nomem, nostack)); } }

pub fn disable_interrupts() { unsafe { asm!("cli"); } }

pub fn enable_interrupts() { unsafe { asm!("sti"); } }

pub fn get_cpu_id() -> u32 {
    let apic_id: u32;
    unsafe {
        asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "shr ebx, 24",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) apic_id,
            out("eax") _,
            out("ecx") _,
            out("edx") _,
            options(nomem)
        );
    }
    apic_id
}

pub fn init_cpu_features() {
    unsafe {
        let cr0: u64;
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack));
        let cr0 = (cr0 | (1 << 1)) & !(1 << 2);
        asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack));
        let cr4: u64;
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
        let cr4 = cr4 | (1 << 9) | (1 << 10) | (1 << 18);
        asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack));
        let mut xcr0: u64 = 1;
        xcr0 |= 1 << 1;
        xcr0 |= 1 << 2;
        asm!("xsetbv", in("ecx") 0u32, in("eax") xcr0 as u32, in("edx") (xcr0 >> 32) as u32, options(nomem, nostack));
    }
}
