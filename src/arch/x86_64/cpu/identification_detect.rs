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

use super::cpuid::cpuid;
use super::identification_types::CpuId;
use super::vendor::CpuVendor;

impl CpuId {
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
        let display_family = if family == 0xF { (ext_family as u16) + (family as u16) } else { family as u16 };
        let display_model = if family == 0xF || family == 0x6 { (ext_model << 4) | model } else { model };
        Self { vendor, family, ext_family, model, ext_model, stepping, brand_index,
               clflush_size, max_logical_processors, apic_id, display_family, display_model }
    }
}
