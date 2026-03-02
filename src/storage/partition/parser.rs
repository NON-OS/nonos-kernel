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

extern crate alloc;

use alloc::vec::Vec;

use super::constants::{SECTOR_SIZE, MBR_SIGNATURE, MBR_GPT_PROTECTIVE};
use super::structures::Mbr;
use super::types::{DiskPartitionInfo, PartitionTableType};
use super::gpt::parse_gpt;
use super::mbr::parse_mbr;

pub struct PartitionParser;

impl PartitionParser {
    pub fn parse<F>(read_sector: F, total_sectors: u64) -> Result<DiskPartitionInfo, &'static str>
    where
        F: Fn(u64, &mut [u8]) -> Result<(), &'static str>,
    {
        let mut mbr_buffer = [0u8; SECTOR_SIZE];
        read_sector(0, &mut mbr_buffer)?;

        // SAFETY: Buffer contains valid MBR data
        let mbr = unsafe { &*(mbr_buffer.as_ptr() as *const Mbr) };
        if mbr.signature != MBR_SIGNATURE {
            return Ok(DiskPartitionInfo {
                table_type: PartitionTableType::None,
                disk_guid: None,
                total_sectors,
                sector_size: SECTOR_SIZE as u32,
                partitions: Vec::new(),
                dual_boot_capable: false,
                detected_os: Vec::new(),
            });
        }

        let has_gpt_protective = mbr.partitions.iter()
            .any(|p| p.partition_type == MBR_GPT_PROTECTIVE);

        if has_gpt_protective {
            parse_gpt(read_sector, total_sectors)
        } else {
            parse_mbr(mbr, read_sector, total_sectors)
        }
    }
}
