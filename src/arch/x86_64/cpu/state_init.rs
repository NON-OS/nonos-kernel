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
use super::error::CpuError;
use super::features::CpuFeatures;
use super::frequency::{core_frequency, tsc_frequency};
use super::identification::CpuId;
use super::per_cpu::MAX_CPUS;
use super::state_globals::*;
use super::topology::CpuTopology;
use core::sync::atomic::Ordering;

pub fn init() -> Result<(), CpuError> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(CpuError::AlreadyInitialized);
    }
    unsafe {
        CPU_ID = CpuId::detect();
        CPU_FEATURES = CpuFeatures::detect();
        CACHE_INFO = CacheInfo::detect();
        TOPOLOGY = CpuTopology::detect();
        let tsc_freq = tsc_frequency();
        let core_freq = core_frequency();
        BSP_DATA.cpu_id = 0;
        BSP_DATA.apic_id = CPU_ID.apic_id as u32;
        BSP_DATA.tsc_frequency = tsc_freq;
        BSP_DATA.core_frequency = core_freq;
        BSP_DATA.features = CPU_FEATURES;
        BSP_DATA.cache = CACHE_INFO;
        BSP_DATA.initialized = true;
        CPU_COUNT.store(1, Ordering::Release);
    }
    Ok(())
}

// Load this AP's GDT/TSS before publishing AP_DATA; an exception
// taken with a stale TSS targets the BSP's ISTs.
pub unsafe fn init_ap(cpu_id: u16, apic_id: u32) -> Result<(), CpuError> {
    if cpu_id == 0 || (cpu_id as usize) >= MAX_CPUS {
        return Err(CpuError::InvalidCpuId);
    }
    unsafe {
        super::super::gdt::init_ap(cpu_id as u32).map_err(|_| CpuError::InvalidCpuId)?;
    }
    let idx = cpu_id as usize;
    unsafe {
        AP_DATA[idx].cpu_id = cpu_id;
        AP_DATA[idx].apic_id = apic_id;
        AP_DATA[idx].tsc_frequency = tsc_frequency();
        AP_DATA[idx].core_frequency = core_frequency();
        AP_DATA[idx].features = CpuFeatures::detect();
        AP_DATA[idx].cache = CacheInfo::detect();
        AP_DATA[idx].initialized = true;
    }
    CPU_COUNT.fetch_add(1, Ordering::Release);
    Ok(())
}
