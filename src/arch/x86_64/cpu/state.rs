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

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::error::CpuError;
use super::vendor::CpuVendor;
use super::features::{CpuFeatures, has_feature as check_feature};
use super::cache::CacheInfo;
use super::topology::CpuTopology;
use super::identification::CpuId;
use super::per_cpu::{PerCpuData, MAX_CPUS};
use super::frequency::{tsc_frequency, core_frequency, get_tsc_frequency, get_core_frequency};
use super::cpuid::cpuid_calls;
use super::msr::{msr_reads, msr_writes};

static mut BSP_DATA: PerCpuData = PerCpuData::new();
static mut AP_DATA: [PerCpuData; MAX_CPUS] = {
    const INIT: PerCpuData = PerCpuData::new();
    [INIT; MAX_CPUS]
};

static mut CPU_ID: CpuId = CpuId::new();
static mut CPU_FEATURES: CpuFeatures = CpuFeatures::new();
static mut CACHE_INFO: CacheInfo = CacheInfo {
    l1d_size: 0, l1d_line_size: 0, l1d_assoc: 0,
    l1i_size: 0, l1i_line_size: 0, l1i_assoc: 0,
    l2_size: 0, l2_line_size: 0, l2_assoc: 0,
    l3_size: 0, l3_line_size: 0, l3_assoc: 0,
    line_size: 64,
};
static mut TOPOLOGY: CpuTopology = CpuTopology {
    packages: 0, cores_per_package: 0, threads_per_core: 0,
    logical_processors: 0, physical_cores: 0, smt_width: 0, core_width: 0,
};

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static CPU_COUNT: AtomicU32 = AtomicU32::new(0);

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

pub unsafe fn init_ap(cpu_id: u16, apic_id: u32) -> Result<(), CpuError> {
    if (cpu_id as usize) >= MAX_CPUS {
        return Err(CpuError::InvalidCpuId);
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

#[inline]
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

#[inline]
pub fn cpu_count() -> u32 {
    CPU_COUNT.load(Ordering::Acquire)
}

#[inline]
pub fn current_cpu_id() -> u16 {
    0
}

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
        unsafe {
            if BSP_DATA.initialized {
                Some(BSP_DATA)
            } else {
                None
            }
        }
    } else {
        let idx = cpu_id as usize;
        if idx < MAX_CPUS {
            unsafe {
                if AP_DATA[idx].initialized {
                    Some(AP_DATA[idx])
                } else {
                    None
                }
            }
        } else {
            None
        }
    }
}

pub fn has_feature(name: &str) -> bool {
    check_feature(&features(), name)
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CpuStats {
    pub cpuid_calls: u64,
    pub msr_reads: u64,
    pub msr_writes: u64,
    pub tsc_frequency: u64,
    pub core_frequency: u64,
    pub cpu_count: u32,
    pub initialized: bool,
}

pub fn get_stats() -> CpuStats {
    CpuStats {
        cpuid_calls: cpuid_calls(),
        msr_reads: msr_reads(),
        msr_writes: msr_writes(),
        tsc_frequency: get_tsc_frequency(),
        core_frequency: get_core_frequency(),
        cpu_count: CPU_COUNT.load(Ordering::Relaxed),
        initialized: INITIALIZED.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_messages() {
        assert_eq!(CpuError::None.as_str(), "no error");
        assert_eq!(CpuError::NotInitialized.as_str(), "CPU detection not initialized");
        assert_eq!(CpuError::InvalidCpuId.as_str(), "invalid CPU ID");
    }
}
