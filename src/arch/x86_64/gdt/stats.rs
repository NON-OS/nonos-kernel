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

use core::sync::atomic::Ordering;
use crate::arch::x86_64::gdt::constants::*;
use crate::arch::x86_64::gdt::state::*;

#[derive(Clone, Copy, Debug)]
pub struct Selectors {
    pub kernel_code: u16,
    pub kernel_data: u16,
    pub user_code: u16,
    pub user_data: u16,
    pub tss: u16,
}

impl Selectors {
    pub const fn standard() -> Self {
        Self {
            kernel_code: SEL_KERNEL_CODE,
            kernel_data: SEL_KERNEL_DATA,
            user_code: SEL_USER_CODE,
            user_data: SEL_USER_DATA,
            tss: SEL_TSS,
        }
    }
}

pub fn selectors() -> Selectors {
    Selectors::standard()
}

#[derive(Clone, Copy, Debug, Default)]
pub struct GdtStats {
    pub gdt_loads: u64,
    pub tss_loads: u64,
    pub syscall_setups: u64,
    pub cpu_count: u64,
    pub initialized: bool,
}

pub fn get_stats() -> GdtStats {
    GdtStats {
        gdt_loads: GDT_LOADS.load(Ordering::Relaxed),
        tss_loads: TSS_LOADS.load(Ordering::Relaxed),
        syscall_setups: SYSCALL_SETUPS.load(Ordering::Relaxed),
        cpu_count: CPU_COUNT.load(Ordering::Relaxed),
        initialized: INITIALIZED.load(Ordering::Relaxed),
    }
}
