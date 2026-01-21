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

use core::sync::atomic::{AtomicBool, AtomicU64};
use crate::arch::x86_64::gdt::constants::MAX_CPUS;
use crate::arch::x86_64::gdt::percpu::PerCpuGdt;

pub(crate) static mut BSP_GDT: PerCpuGdt = PerCpuGdt::new();

pub(crate) static mut AP_GDTS: [PerCpuGdt; MAX_CPUS] = {
    const INIT: PerCpuGdt = PerCpuGdt::new();
    [INIT; MAX_CPUS]
};

pub(crate) static INITIALIZED: AtomicBool = AtomicBool::new(false);
pub(crate) static CPU_COUNT: AtomicU64 = AtomicU64::new(0);
pub(crate) static GDT_LOADS: AtomicU64 = AtomicU64::new(0);
pub(crate) static TSS_LOADS: AtomicU64 = AtomicU64::new(0);
pub(crate) static SYSCALL_SETUPS: AtomicU64 = AtomicU64::new(0);
