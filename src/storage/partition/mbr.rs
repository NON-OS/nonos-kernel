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

use alloc::{string::String, vec::Vec};

use super::constants::{mbr_types, SECTOR_SIZE, MBR_SIGNATURE};
use super::structures::Mbr;
use super::types::{
    DiskPartitionInfo, PartitionTableType, Partition, PartitionType, DetectedOs,
};
use super::utils::detect_os_from_partition;

pub fn parse_mbr<F>(
    mbr: &Mbr,
    read_sector: F,
    total_sectors: u64,
) -> Result<DiskPartitionInfo, &'static str>
where
    F: Fn(u64, &mut [u8]) -> Result<(), &'static str>,
{
    let mut partitions = Vec::new();
    let mut detected_os = Vec::new();
    let mut partition_number = 1u32;

    for mbr_entry in &mbr.partitions {
        if mbr_entry.partition_type == 0 || mbr_entry.size_sectors == 0 {
            continue;
        }

        let partition_type = PartitionType::LegacyMbr(mbr_entry.partition_type);

        let partition = Partition {
            number: partition_number,
            start_lba: mbr_entry.start_lba as u64,
            end_lba: mbr_entry.start_lba as u64 + mbr_entry.size_sectors as u64 - 1,
            size_sectors: mbr_entry.size_sectors as u64,
            size_bytes: mbr_entry.size_sectors as u64 * SECTOR_SIZE as u64,
            partition_type: partition_type.clone(),
            name: String::new(),
            guid: None,
            bootable: mbr_entry.boot_indicator == 0x80,
            active: mbr_entry.boot_indicator == 0x80,
            filesystem: None,
        };

        if let Some(os) = detect_os_from_partition(&partition) {
            detected_os.push(os);
        }

        partitions.push(partition);
        partition_number += 1;

        if mbr_entry.partition_type == mbr_types::EXTENDED
            || mbr_entry.partition_type == mbr_types::EXTENDED_LBA
        {
            parse_extended_partitions(
                &read_sector,
                mbr_entry.start_lba as u64,
                mbr_entry.start_lba as u64,
                &mut partitions,
                &mut detected_os,
                &mut partition_number,
            )?;
        }
    }

    let dual_boot_capable = !detected_os.is_empty();

    Ok(DiskPartitionInfo {
        table_type: PartitionTableType::Mbr,
        disk_guid: None,
        total_sectors,
        sector_size: SECTOR_SIZE as u32,
        partitions,
        dual_boot_capable,
        detected_os,
    })
}

fn parse_extended_partitions<F>(
    read_sector: &F,
    base_lba: u64,
    current_lba: u64,
    partitions: &mut Vec<Partition>,
    detected_os: &mut Vec<DetectedOs>,
    partition_number: &mut u32,
) -> Result<(), &'static str>
where
    F: Fn(u64, &mut [u8]) -> Result<(), &'static str>,
{
    let mut next_lba = current_lba;
    let max_iterations = 128;
    let mut iterations = 0;

    while next_lba != 0 && iterations < max_iterations {
        let mut ebr_buffer = [0u8; SECTOR_SIZE];
        read_sector(next_lba, &mut ebr_buffer)?;

        // SAFETY: Buffer contains valid EBR data
        let ebr = unsafe { &*(ebr_buffer.as_ptr() as *const Mbr) };

        if ebr.signature != MBR_SIGNATURE {
            break;
        }

        let logical = &ebr.partitions[0];
        if logical.partition_type != 0 && logical.size_sectors != 0 {
            let partition_type = PartitionType::LegacyMbr(logical.partition_type);
            let start_lba = next_lba + logical.start_lba as u64;

            let partition = Partition {
                number: *partition_number,
                start_lba,
                end_lba: start_lba + logical.size_sectors as u64 - 1,
                size_sectors: logical.size_sectors as u64,
                size_bytes: logical.size_sectors as u64 * SECTOR_SIZE as u64,
                partition_type: partition_type.clone(),
                name: String::new(),
                guid: None,
                bootable: logical.boot_indicator == 0x80,
                active: false,
                filesystem: None,
            };

            if let Some(os) = detect_os_from_partition(&partition) {
                detected_os.push(os);
            }

            partitions.push(partition);
            *partition_number += 1;
        }

        let next_entry = &ebr.partitions[1];
        if next_entry.partition_type == mbr_types::EXTENDED
            || next_entry.partition_type == mbr_types::EXTENDED_LBA
        {
            next_lba = base_lba + next_entry.start_lba as u64;
        } else {
            break;
        }

        iterations += 1;
    }

    Ok(())
}
