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

use super::constants::{SECTOR_SIZE, GPT_SIGNATURE};
use super::structures::{GptHeader, GptPartitionEntry};
use super::types::{
    DiskPartitionInfo, PartitionTableType, Partition, PartitionType, DetectedOs,
};
use super::utils::{guid_to_partition_type, utf16le_to_string, detect_os_from_partition};

pub fn parse_gpt<F>(read_sector: F, total_sectors: u64) -> Result<DiskPartitionInfo, &'static str>
where
    F: Fn(u64, &mut [u8]) -> Result<(), &'static str>,
{
    let mut gpt_buffer = [0u8; SECTOR_SIZE];
    read_sector(1, &mut gpt_buffer)?;

    // SAFETY: Buffer contains valid GPT header data
    let header = unsafe { &*(gpt_buffer.as_ptr() as *const GptHeader) };

    if header.signature != GPT_SIGNATURE {
        return Err("Invalid GPT signature");
    }

    let mut partitions = Vec::new();
    let mut detected_os = Vec::new();

    let entries_per_sector = SECTOR_SIZE / header.partition_entry_size as usize;
    let entry_sectors = (header.num_partition_entries as usize + entries_per_sector - 1)
        / entries_per_sector;

    let mut entry_buffer = [0u8; SECTOR_SIZE];
    let mut partition_number = 1u32;

    for sector_offset in 0..entry_sectors {
        let sector_lba = header.partition_entry_lba + sector_offset as u64;
        read_sector(sector_lba, &mut entry_buffer)?;

        for entry_idx in 0..entries_per_sector {
            if partition_number > header.num_partition_entries {
                break;
            }

            let entry_offset = entry_idx * header.partition_entry_size as usize;
            if entry_offset + header.partition_entry_size as usize > SECTOR_SIZE {
                break;
            }

            // SAFETY: Entry offset is bounds checked
            let entry = unsafe {
                &*(entry_buffer[entry_offset..].as_ptr() as *const GptPartitionEntry)
            };

            if entry.type_guid == [0u8; 16] {
                partition_number += 1;
                continue;
            }

            let partition_type = guid_to_partition_type(&entry.type_guid);
            let name_copy: [u16; 36] = entry.name;
            let name = utf16le_to_string(&name_copy);

            let partition = Partition {
                number: partition_number,
                start_lba: entry.first_lba,
                end_lba: entry.last_lba,
                size_sectors: entry.last_lba - entry.first_lba + 1,
                size_bytes: (entry.last_lba - entry.first_lba + 1) * SECTOR_SIZE as u64,
                partition_type: partition_type.clone(),
                name,
                guid: Some(entry.partition_guid),
                bootable: partition_type.is_bootable_type(),
                active: (entry.attributes & 0x04) != 0,
                filesystem: None,
            };

            if let Some(os) = detect_os_from_partition(&partition) {
                detected_os.push(os);
            }

            partitions.push(partition);
            partition_number += 1;
        }
    }

    let dual_boot_capable = !detected_os.is_empty() ||
        partitions.iter().any(|p| matches!(p.partition_type, PartitionType::EfiSystem));

    Ok(DiskPartitionInfo {
        table_type: PartitionTableType::Gpt,
        disk_guid: Some(header.disk_guid),
        total_sectors,
        sector_size: SECTOR_SIZE as u32,
        partitions,
        dual_boot_capable,
        detected_os,
    })
}
