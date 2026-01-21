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

use super::cpuid::cpuid;
use super::vendor::CpuVendor;

#[derive(Debug, Clone, Copy)]
pub struct CpuId {
    pub vendor: CpuVendor,
    pub family: u8,
    pub ext_family: u8,
    pub model: u8,
    pub ext_model: u8,
    pub stepping: u8,
    pub brand_index: u8,
    pub clflush_size: u8,
    pub max_logical_processors: u8,
    pub apic_id: u8,
    pub display_family: u16,
    pub display_model: u8,
}

impl CpuId {
    pub const fn new() -> Self {
        Self {
            vendor: CpuVendor::Unknown,
            family: 0,
            ext_family: 0,
            model: 0,
            ext_model: 0,
            stepping: 0,
            brand_index: 0,
            clflush_size: 0,
            max_logical_processors: 0,
            apic_id: 0,
            display_family: 0,
            display_model: 0,
        }
    }

    pub fn detect() -> Self {
        let (_, ebx, ecx, edx) = cpuid(0);
        let vendor = CpuVendor::from_cpuid_string(ebx, ecx, edx);
        let (eax, ebx, _, _) = cpuid(1);
        let stepping = (eax & 0xF) as u8;
        let model = ((eax >> 4) & 0xF) as u8;
        let family = ((eax >> 8) & 0xF) as u8;
        let ext_model = ((eax >> 16) & 0xF) as u8;
        let ext_family = ((eax >> 20) & 0xFF) as u8;
        let brand_index = (ebx & 0xFF) as u8;
        let clflush_size = ((ebx >> 8) & 0xFF) as u8;
        let max_logical_processors = ((ebx >> 16) & 0xFF) as u8;
        let apic_id = ((ebx >> 24) & 0xFF) as u8;
        let display_family = if family == 0xF {
            (ext_family as u16) + (family as u16)
        } else {
            family as u16
        };

        let display_model = if family == 0xF || family == 0x6 {
            (ext_model << 4) | model
        } else {
            model
        };

        Self {
            vendor,
            family,
            ext_family,
            model,
            ext_model,
            stepping,
            brand_index,
            clflush_size,
            max_logical_processors,
            apic_id,
            display_family,
            display_model,
        }
    }
}
