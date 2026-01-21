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

use super::cache::CacheInfo;
use super::error::CpuError;
use super::features::CpuFeatures;
use super::identification::CpuId;
use super::per_cpu::PerCpuData;
use super::state::{self, CpuStats};
use super::topology::CpuTopology;
use super::vendor::CpuVendor;

#[inline]
pub fn init() -> Result<(), CpuError> {
    state::init()
}

#[inline]
pub unsafe fn init_ap(cpu_id: u16, apic_id: u32) -> Result<(), CpuError> {
    unsafe { state::init_ap(cpu_id, apic_id) }
}

#[inline]
pub fn is_initialized() -> bool {
    state::is_initialized()
}

#[inline]
pub fn vendor() -> CpuVendor {
    state::vendor()
}

#[inline]
pub fn cpu_id() -> CpuId {
    state::cpu_id()
}

#[inline]
pub fn features() -> CpuFeatures {
    state::features()
}

#[inline]
pub fn cache_info() -> CacheInfo {
    state::cache_info()
}

#[inline]
pub fn topology() -> CpuTopology {
    state::topology()
}

#[inline]
pub fn per_cpu_data(cpu_id: u16) -> Option<PerCpuData> {
    state::per_cpu_data(cpu_id)
}

#[inline]
pub fn cpu_count() -> u32 {
    state::cpu_count()
}

#[inline]
pub fn current_cpu_id() -> u16 {
    state::current_cpu_id()
}

#[inline]
pub fn has_feature(name: &str) -> bool {
    state::has_feature(name)
}

#[inline]
pub fn get_stats() -> CpuStats {
    state::get_stats()
}
