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

use super::super::types::LbaFormat;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct Namespace {
    pub nsid: u32,
    pub size_blocks: u64,
    pub capacity_blocks: u64,
    pub utilization_blocks: u64,
    pub block_size: u32,
    pub block_size_shift: u8,
    pub metadata_size: u16,
    pub formatted_lba_size: u8,
    pub features: NamespaceFeatures,
    pub protection: DataProtection,
    pub multi_path: MultiPathCapabilities,
    pub metadata_capabilities: u8,
    pub reservation_capabilities: u8,
    pub lba_formats: Vec<LbaFormat>,
    pub(super) active_lba_format_index: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct NamespaceFeatures {
    pub thin_provisioning: bool,
    pub ns_atomic_write_unit: bool,
    pub deallocated_error: bool,
    pub guid_reuse: bool,
    pub optimal_io_boundary: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct DataProtection {
    pub type1_supported: bool,
    pub type2_supported: bool,
    pub type3_supported: bool,
    pub first_eight_bytes: bool,
    pub last_eight_bytes: bool,
    pub enabled_type: u8,
    pub first_location: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct MultiPathCapabilities {
    pub shared_namespace: bool,
}
