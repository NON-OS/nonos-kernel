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

use alloc::vec::Vec;
use super::types::LbaFormat;
use super::error::NvmeError;
use super::constants::{
    IDENTIFY_NS_NSZE_OFFSET, IDENTIFY_NS_NCAP_OFFSET, IDENTIFY_NS_NUSE_OFFSET,
    IDENTIFY_NS_NSFEAT_OFFSET, IDENTIFY_NS_NLBAF_OFFSET, IDENTIFY_NS_FLBAS_OFFSET,
    IDENTIFY_NS_MC_OFFSET, IDENTIFY_NS_DPC_OFFSET, IDENTIFY_NS_DPS_OFFSET,
    IDENTIFY_NS_NMIC_OFFSET, IDENTIFY_NS_RESCAP_OFFSET, IDENTIFY_NS_LBAF_OFFSET,
};

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
    pub lba_formats: Vec<LbaFormat>,
    active_lba_format_index: u8,
}

impl Namespace {
    pub fn from_identify_data(nsid: u32, data: &[u8; 4096]) -> Result<Self, NvmeError> {
        let size_blocks = u64::from_le_bytes([
            data[IDENTIFY_NS_NSZE_OFFSET],
            data[IDENTIFY_NS_NSZE_OFFSET + 1],
            data[IDENTIFY_NS_NSZE_OFFSET + 2],
            data[IDENTIFY_NS_NSZE_OFFSET + 3],
            data[IDENTIFY_NS_NSZE_OFFSET + 4],
            data[IDENTIFY_NS_NSZE_OFFSET + 5],
            data[IDENTIFY_NS_NSZE_OFFSET + 6],
            data[IDENTIFY_NS_NSZE_OFFSET + 7],
        ]);

        let capacity_blocks = u64::from_le_bytes([
            data[IDENTIFY_NS_NCAP_OFFSET],
            data[IDENTIFY_NS_NCAP_OFFSET + 1],
            data[IDENTIFY_NS_NCAP_OFFSET + 2],
            data[IDENTIFY_NS_NCAP_OFFSET + 3],
            data[IDENTIFY_NS_NCAP_OFFSET + 4],
            data[IDENTIFY_NS_NCAP_OFFSET + 5],
            data[IDENTIFY_NS_NCAP_OFFSET + 6],
            data[IDENTIFY_NS_NCAP_OFFSET + 7],
        ]);

        let utilization_blocks = u64::from_le_bytes([
            data[IDENTIFY_NS_NUSE_OFFSET],
            data[IDENTIFY_NS_NUSE_OFFSET + 1],
            data[IDENTIFY_NS_NUSE_OFFSET + 2],
            data[IDENTIFY_NS_NUSE_OFFSET + 3],
            data[IDENTIFY_NS_NUSE_OFFSET + 4],
            data[IDENTIFY_NS_NUSE_OFFSET + 5],
            data[IDENTIFY_NS_NUSE_OFFSET + 6],
            data[IDENTIFY_NS_NUSE_OFFSET + 7],
        ]);

        let nsfeat = data[IDENTIFY_NS_NSFEAT_OFFSET];
        let nlbaf = data[IDENTIFY_NS_NLBAF_OFFSET];
        let flbas = data[IDENTIFY_NS_FLBAS_OFFSET];
        let mc = data[IDENTIFY_NS_MC_OFFSET];
        let dpc = data[IDENTIFY_NS_DPC_OFFSET];
        let dps = data[IDENTIFY_NS_DPS_OFFSET];
        let nmic = data[IDENTIFY_NS_NMIC_OFFSET];
        let rescap = data[IDENTIFY_NS_RESCAP_OFFSET];
        let active_lba_format_index = flbas & 0x0F;
        let num_lba_formats = (nlbaf as usize) + 1;
        let mut lba_formats = Vec::with_capacity(num_lba_formats);
        for i in 0..num_lba_formats {
            let offset = IDENTIFY_NS_LBAF_OFFSET + i * 4;
            let dword = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            lba_formats.push(LbaFormat::from_dword(dword));
        }

        let active_format = lba_formats
            .get(active_lba_format_index as usize)
            .ok_or(NvmeError::InvalidNamespaceId)?;

        let block_size_shift = active_format.lba_data_size_shift;
        let block_size = if block_size_shift > 0 {
            1u32 << block_size_shift
        } else {
            512
        };
        let metadata_size = active_format.metadata_size;
        let features = NamespaceFeatures {
            thin_provisioning: (nsfeat & 0x01) != 0,
            ns_atomic_write_unit: (nsfeat & 0x02) != 0,
            deallocated_error: (nsfeat & 0x04) != 0,
            guid_reuse: (nsfeat & 0x08) != 0,
            optimal_io_boundary: (nsfeat & 0x10) != 0,
        };

        let protection = DataProtection {
            type1_supported: (dpc & 0x01) != 0,
            type2_supported: (dpc & 0x02) != 0,
            type3_supported: (dpc & 0x04) != 0,
            first_eight_bytes: (dpc & 0x08) != 0,
            last_eight_bytes: (dpc & 0x10) != 0,
            enabled_type: dps & 0x07,
            first_location: (dps & 0x08) != 0,
        };

        let multi_path = MultiPathCapabilities {
            shared_namespace: (nmic & 0x01) != 0,
        };

        Ok(Self {
            nsid,
            size_blocks,
            capacity_blocks,
            utilization_blocks,
            block_size,
            block_size_shift,
            metadata_size,
            formatted_lba_size: flbas,
            features,
            protection,
            multi_path,
            lba_formats,
            active_lba_format_index,
        })
    }

    #[inline]
    pub const fn nsid(&self) -> u32 {
        self.nsid
    }

    #[inline]
    pub const fn size_bytes(&self) -> u64 {
        self.size_blocks * (self.block_size as u64)
    }

    #[inline]
    pub const fn capacity_bytes(&self) -> u64 {
        self.capacity_blocks * (self.block_size as u64)
    }

    #[inline]
    pub const fn block_size(&self) -> u32 {
        self.block_size
    }

    #[inline]
    pub const fn block_count(&self) -> u64 {
        self.size_blocks
    }

    pub fn validate_lba_range(&self, start_lba: u64, block_count: u16) -> Result<(), NvmeError> {
        if block_count == 0 {
            return Err(NvmeError::InvalidBlockCount);
        }

        let end_lba = start_lba
            .checked_add(block_count as u64)
            .ok_or(NvmeError::LbaRangeOverflow)?;

        if end_lba > self.size_blocks {
            return Err(NvmeError::LbaExceedsCapacity);
        }

        Ok(())
    }

    pub fn blocks_to_bytes(&self, blocks: u64) -> u64 {
        blocks << self.block_size_shift
    }

    pub fn bytes_to_blocks(&self, bytes: u64) -> u64 {
        bytes >> self.block_size_shift
    }

    pub fn bytes_to_blocks_ceil(&self, bytes: u64) -> u64 {
        let mask = (1u64 << self.block_size_shift) - 1;
        (bytes + mask) >> self.block_size_shift
    }

    pub fn active_lba_format(&self) -> Option<&LbaFormat> {
        self.lba_formats.get(self.active_lba_format_index as usize)
    }

    pub fn supports_thin_provisioning(&self) -> bool {
        self.features.thin_provisioning
    }

    pub fn is_shared(&self) -> bool {
        self.multi_path.shared_namespace
    }

    pub fn has_data_protection(&self) -> bool {
        self.protection.enabled_type != 0
    }

    pub fn size_gb(&self) -> f64 {
        (self.size_bytes() as f64) / (1024.0 * 1024.0 * 1024.0)
    }
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

pub struct NamespaceManager {
    namespaces: Vec<Namespace>,
}

impl NamespaceManager {
    pub const fn new() -> Self {
        Self {
            namespaces: Vec::new(),
        }
    }

    pub fn add(&mut self, ns: Namespace) {
        if self.get(ns.nsid).is_none() {
            self.namespaces.push(ns);
            self.namespaces.sort_by_key(|n| n.nsid);
        }
    }

    pub fn remove(&mut self, nsid: u32) -> Option<Namespace> {
        if let Some(pos) = self.namespaces.iter().position(|n| n.nsid == nsid) {
            Some(self.namespaces.remove(pos))
        } else {
            None
        }
    }

    pub fn get(&self, nsid: u32) -> Option<&Namespace> {
        self.namespaces.iter().find(|n| n.nsid == nsid)
    }

    pub fn get_mut(&mut self, nsid: u32) -> Option<&mut Namespace> {
        self.namespaces.iter_mut().find(|n| n.nsid == nsid)
    }

    pub fn first(&self) -> Option<&Namespace> {
        self.namespaces.first()
    }

    pub fn count(&self) -> usize {
        self.namespaces.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Namespace> {
        self.namespaces.iter()
    }

    pub fn nsids(&self) -> Vec<u32> {
        self.namespaces.iter().map(|n| n.nsid).collect()
    }

    pub fn clear(&mut self) {
        self.namespaces.clear();
    }

    pub fn total_capacity_bytes(&self) -> u64 {
        self.namespaces.iter().map(|n| n.capacity_bytes()).sum()
    }

    pub fn total_size_bytes(&self) -> u64 {
        self.namespaces.iter().map(|n| n.size_bytes()).sum()
    }
}

impl Default for NamespaceManager {
    fn default() -> Self {
        Self::new()
    }
}

pub fn parse_namespace_list(data: &[u8; 4096]) -> Vec<u32> {
    let mut nsids = Vec::new();
    for i in 0..(4096 / 4) {
        let offset = i * 4;
        let nsid = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        if nsid == 0 {
            break;
        }

        nsids.push(nsid);
    }

    nsids
}
