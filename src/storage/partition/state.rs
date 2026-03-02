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

use alloc::{string::String, vec::Vec, format};
use core::sync::atomic::{AtomicU32, Ordering};
use spin::RwLock;

use super::types::{
    DiskPartitionInfo, DetectedOs, Partition, PartitionType, OsType, BootMenuEntry,
};
use super::parser::PartitionParser;

static PARTITION_CACHE: RwLock<Vec<DiskPartitionInfo>> = RwLock::new(Vec::new());
static DISK_ID_COUNTER: AtomicU32 = AtomicU32::new(0);

pub fn scan_disk_partitions<F>(
    read_sector: F,
    total_sectors: u64,
) -> Result<u32, &'static str>
where
    F: Fn(u64, &mut [u8]) -> Result<(), &'static str>,
{
    let disk_info = PartitionParser::parse(read_sector, total_sectors)?;
    let disk_id = DISK_ID_COUNTER.fetch_add(1, Ordering::SeqCst);

    let mut cache = PARTITION_CACHE.write();
    cache.push(disk_info);

    Ok(disk_id)
}

pub fn get_disk_partitions(disk_id: u32) -> Option<DiskPartitionInfo> {
    let cache = PARTITION_CACHE.read();
    cache.get(disk_id as usize).cloned()
}

pub fn get_all_detected_os() -> Vec<(u32, DetectedOs)> {
    let cache = PARTITION_CACHE.read();
    let mut result = Vec::new();

    for (disk_id, disk_info) in cache.iter().enumerate() {
        for os in &disk_info.detected_os {
            result.push((disk_id as u32, os.clone()));
        }
    }

    result
}

pub fn find_efi_system_partition() -> Option<(u32, Partition)> {
    let cache = PARTITION_CACHE.read();

    for (disk_id, disk_info) in cache.iter().enumerate() {
        for partition in &disk_info.partitions {
            if matches!(partition.partition_type, PartitionType::EfiSystem) {
                return Some((disk_id as u32, partition.clone()));
            }
        }
    }

    None
}

pub fn find_nonos_partition() -> Option<(u32, Partition)> {
    let cache = PARTITION_CACHE.read();

    for (disk_id, disk_info) in cache.iter().enumerate() {
        for partition in &disk_info.partitions {
            if matches!(partition.partition_type, PartitionType::NonosZerostate) {
                return Some((disk_id as u32, partition.clone()));
            }
        }
    }

    None
}

pub fn is_dual_boot_capable() -> bool {
    let cache = PARTITION_CACHE.read();
    cache.iter().any(|disk| disk.dual_boot_capable)
}

pub fn get_boot_menu_entries() -> Vec<BootMenuEntry> {
    let mut entries = Vec::new();
    let cache = PARTITION_CACHE.read();

    entries.push(BootMenuEntry {
        name: String::from("NONOS ZeroState"),
        disk_id: 0,
        partition_number: 0,
        os_type: OsType::NonOs,
        is_default: true,
        boot_loader_path: None,
    });

    for (disk_id, disk_info) in cache.iter().enumerate() {
        for os in &disk_info.detected_os {
            if os.os_type != OsType::NonOs {
                entries.push(BootMenuEntry {
                    name: format!("{:?} (Disk {}, Partition {})",
                        os.os_type, disk_id, os.partition_number),
                    disk_id: disk_id as u32,
                    partition_number: os.partition_number,
                    os_type: os.os_type,
                    is_default: false,
                    boot_loader_path: BootMenuEntry::get_boot_loader_path(os.os_type),
                });
            }
        }
    }

    entries
}

pub fn init() -> Result<(), &'static str> {
    crate::log::logger::log_info!("Partition detection subsystem initialized");
    Ok(())
}
