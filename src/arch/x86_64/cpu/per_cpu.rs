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

use super::features::CpuFeatures;
use super::cache::CacheInfo;

pub const MAX_CPUS: usize = 256;

#[derive(Debug, Clone, Copy)]
pub struct PerCpuData {
    pub cpu_id: u16,
    pub apic_id: u32,
    pub tsc_frequency: u64,
    pub core_frequency: u64,
    pub features: CpuFeatures,
    pub cache: CacheInfo,
    pub initialized: bool,
}

impl PerCpuData {
    pub const fn new() -> Self {
        Self {
            cpu_id: 0,
            apic_id: 0,
            tsc_frequency: 0,
            core_frequency: 0,
            features: CpuFeatures::new(),
            cache: CacheInfo {
                l1d_size: 0, l1d_line_size: 0, l1d_assoc: 0,
                l1i_size: 0, l1i_line_size: 0, l1i_assoc: 0,
                l2_size: 0, l2_line_size: 0, l2_assoc: 0,
                l3_size: 0, l3_line_size: 0, l3_assoc: 0,
                line_size: 64,
            },
            initialized: false,
        }
    }
}
