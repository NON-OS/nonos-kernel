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

use super::super::constants::{
    IDENTIFY_NS_DPC_OFFSET, IDENTIFY_NS_DPS_OFFSET, IDENTIFY_NS_FLBAS_OFFSET,
    IDENTIFY_NS_LBAF_OFFSET, IDENTIFY_NS_MC_OFFSET, IDENTIFY_NS_NCAP_OFFSET,
    IDENTIFY_NS_NLBAF_OFFSET, IDENTIFY_NS_NMIC_OFFSET, IDENTIFY_NS_NSFEAT_OFFSET,
    IDENTIFY_NS_NSZE_OFFSET, IDENTIFY_NS_NUSE_OFFSET, IDENTIFY_NS_RESCAP_OFFSET,
};
use super::super::error::NvmeError;
use super::super::types::LbaFormat;
use super::types::{DataProtection, MultiPathCapabilities, Namespace, NamespaceFeatures};
use alloc::vec::Vec;

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
        let (nsfeat, nlbaf, flbas) = (
            data[IDENTIFY_NS_NSFEAT_OFFSET],
            data[IDENTIFY_NS_NLBAF_OFFSET],
            data[IDENTIFY_NS_FLBAS_OFFSET],
        );
        let (mc, dpc, dps, nmic, rescap) = (
            data[IDENTIFY_NS_MC_OFFSET],
            data[IDENTIFY_NS_DPC_OFFSET],
            data[IDENTIFY_NS_DPS_OFFSET],
            data[IDENTIFY_NS_NMIC_OFFSET],
            data[IDENTIFY_NS_RESCAP_OFFSET],
        );
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
        let block_size = if block_size_shift > 0 { 1u32 << block_size_shift } else { 512 };
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
        let multi_path = MultiPathCapabilities { shared_namespace: (nmic & 0x01) != 0 };
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
            metadata_capabilities: mc,
            reservation_capabilities: rescap,
            lba_formats,
            active_lba_format_index,
        })
    }
}
