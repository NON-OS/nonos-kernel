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

use super::cache::CacheInfo;
use super::features::{CpuFeatures, has_feature as check_feature};
use super::identification::CpuId;
use super::per_cpu::{PerCpuData, MAX_CPUS};
use super::state_globals::*;
use super::topology::CpuTopology;
use super::vendor::CpuVendor;

pub fn vendor() -> CpuVendor {
    unsafe { CPU_ID.vendor }
}

pub fn cpu_id() -> CpuId {
    unsafe { CPU_ID }
}

pub fn features() -> CpuFeatures {
    unsafe { CPU_FEATURES }
}

pub fn cache_info() -> CacheInfo {
    unsafe { CACHE_INFO }
}

pub fn topology() -> CpuTopology {
    unsafe { TOPOLOGY }
}

pub fn per_cpu_data(cpu_id: u16) -> Option<PerCpuData> {
    if cpu_id == 0 {
        unsafe { if BSP_DATA.initialized { Some(BSP_DATA) } else { None } }
    } else {
        let idx = cpu_id as usize;
        if idx < MAX_CPUS {
            unsafe { if AP_DATA[idx].initialized { Some(AP_DATA[idx]) } else { None } }
        } else {
            None
        }
    }
}

#[inline]
pub fn current_cpu_id() -> u16 {
    let apic_id: u32;
    unsafe {
        core::arch::asm!(
            "push rbx", "mov eax, 1", "cpuid", "shr ebx, 24", "mov {0:e}, ebx", "pop rbx",
            out(reg) apic_id, out("eax") _, out("ecx") _, out("edx") _, options(nomem)
        );
    }
    apic_id as u16
}

pub fn has_feature(name: &str) -> bool {
    check_feature(&features(), name)
}
