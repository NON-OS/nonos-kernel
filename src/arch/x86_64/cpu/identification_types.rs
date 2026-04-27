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
}
