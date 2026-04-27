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
use super::features::CpuFeatures;
use super::identification::CpuId;
use super::per_cpu::{PerCpuData, MAX_CPUS};
use super::topology::CpuTopology;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

pub static mut BSP_DATA: PerCpuData = PerCpuData::new();
pub static mut AP_DATA: [PerCpuData; MAX_CPUS] = {
    const INIT: PerCpuData = PerCpuData::new();
    [INIT; MAX_CPUS]
};
pub static mut CPU_ID: CpuId = CpuId::new();
pub static mut CPU_FEATURES: CpuFeatures = CpuFeatures::new();
pub static mut CACHE_INFO: CacheInfo = CacheInfo {
    l1d_size: 0,
    l1d_line_size: 0,
    l1d_assoc: 0,
    l1i_size: 0,
    l1i_line_size: 0,
    l1i_assoc: 0,
    l2_size: 0,
    l2_line_size: 0,
    l2_assoc: 0,
    l3_size: 0,
    l3_line_size: 0,
    l3_assoc: 0,
    line_size: 64,
};
pub static mut TOPOLOGY: CpuTopology = CpuTopology {
    packages: 0,
    cores_per_package: 0,
    threads_per_core: 0,
    logical_processors: 0,
    physical_cores: 0,
    smt_width: 0,
    core_width: 0,
};
pub static INITIALIZED: AtomicBool = AtomicBool::new(false);
pub static CPU_COUNT: AtomicU32 = AtomicU32::new(0);

#[inline]
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

#[inline]
pub fn cpu_count() -> u32 {
    CPU_COUNT.load(Ordering::Acquire)
}
