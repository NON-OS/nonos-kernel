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

use crate::storage::block::BlockResult;
use super::super::types::*;
use super::super::{serial_println, SECTOR_BUFFER};

pub fn read_fat_entry(
    fs: &Fat32,
    cluster: u32,
    read_fn: fn(u8, u64, &mut [u8]) -> BlockResult<()>,
) -> BlockResult<u32> {
    let fat_sector = fs.fat_sector(cluster);
    let fat_offset = fs.fat_offset(cluster) as usize;

    // SAFETY: SECTOR_BUFFER is a kernel-internal buffer for FAT32 I/O.
    let sector_buf = unsafe { &mut SECTOR_BUFFER[..fs.bytes_per_sector as usize] };
    read_fn(fs.device_id, fat_sector as u64, sector_buf)?;

    let entry = u32::from_le_bytes([
        sector_buf[fat_offset],
        sector_buf[fat_offset + 1],
        sector_buf[fat_offset + 2],
        sector_buf[fat_offset + 3],
    ]);

    Ok(entry & FAT32_MASK)
}

pub fn is_eof(cluster: u32) -> bool {
    cluster >= FAT32_EOC
}

pub fn is_bad_cluster(cluster: u32) -> bool {
    cluster == FAT32_BAD
}

pub fn is_free_cluster(cluster: u32) -> bool {
    cluster == FAT32_FREE
}

pub fn write_fat_entry(
    fs: &Fat32,
    cluster: u32,
    value: u32,
    read_fn: fn(u8, u64, &mut [u8]) -> BlockResult<()>,
    write_fn: fn(u8, u64, &[u8]) -> BlockResult<()>,
) -> BlockResult<()> {
    let fat_sector = fs.fat_sector(cluster);
    let fat_offset = fs.fat_offset(cluster) as usize;

    // SAFETY: SECTOR_BUFFER is a kernel-internal buffer for FAT32 I/O.
    let sector_buf = unsafe { &mut SECTOR_BUFFER[..fs.bytes_per_sector as usize] };
    read_fn(fs.device_id, fat_sector as u64, sector_buf)?;

    let masked_value = (value & FAT32_MASK) | (sector_buf[fat_offset + 3] as u32 & 0xF0000000);
    sector_buf[fat_offset..fat_offset + 4].copy_from_slice(&masked_value.to_le_bytes());

    write_fn(fs.device_id, fat_sector as u64, sector_buf)?;

    if fs.num_fats > 1 {
        let backup_sector = fat_sector + fs.fat_size;
        write_fn(fs.device_id, backup_sector as u64, sector_buf)?;
    }

    Ok(())
}

pub fn find_free_cluster(
    fs: &Fat32,
    read_fn: fn(u8, u64, &mut [u8]) -> BlockResult<()>,
) -> BlockResult<Option<u32>> {
    let total_clusters = (fs.total_sectors - fs.first_data_sector) / fs.sectors_per_cluster as u32;

    for cluster in 2..total_clusters + 2 {
        let entry = read_fat_entry(fs, cluster, read_fn)?;
        if is_free_cluster(entry) {
            return Ok(Some(cluster));
        }
    }

    Ok(None)
}

pub fn allocate_cluster_chain(
    fs: &Fat32,
    count: u32,
    read_fn: fn(u8, u64, &mut [u8]) -> BlockResult<()>,
    write_fn: fn(u8, u64, &[u8]) -> BlockResult<()>,
) -> BlockResult<Option<u32>> {
    if count == 0 {
        return Ok(None);
    }

    let mut first_cluster: Option<u32> = None;
    let mut prev_cluster: Option<u32> = None;
    let mut allocated = 0u32;

    let total_clusters = (fs.total_sectors - fs.first_data_sector) / fs.sectors_per_cluster as u32;

    for cluster in 2..total_clusters + 2 {
        if allocated >= count {
            break;
        }

        let entry = read_fat_entry(fs, cluster, read_fn)?;
        if !is_free_cluster(entry) {
            continue;
        }

        if first_cluster.is_none() {
            first_cluster = Some(cluster);
        }

        if let Some(prev) = prev_cluster {
            write_fat_entry(fs, prev, cluster, read_fn, write_fn)?;
        }

        prev_cluster = Some(cluster);
        allocated += 1;
    }

    if let Some(last) = prev_cluster {
        write_fat_entry(fs, last, FAT32_EOC, read_fn, write_fn)?;
    }

    if allocated < count {
        serial_println(b"[FAT32] WARNING: Not enough free clusters");
        return Ok(None);
    }

    Ok(first_cluster)
}

pub fn free_cluster_chain(
    fs: &Fat32,
    start_cluster: u32,
    read_fn: fn(u8, u64, &mut [u8]) -> BlockResult<()>,
    write_fn: fn(u8, u64, &[u8]) -> BlockResult<()>,
) -> BlockResult<u32> {
    if start_cluster < 2 || is_eof(start_cluster) || is_free_cluster(start_cluster) {
        return Ok(0);
    }

    let mut freed = 0u32;
    let mut cluster = start_cluster;

    while !is_eof(cluster) && !is_free_cluster(cluster) && cluster >= 2 {
        let next = read_fat_entry(fs, cluster, read_fn)?;
        write_fat_entry(fs, cluster, FAT32_FREE, read_fn, write_fn)?;
        freed += 1;
        cluster = next;
    }

    Ok(freed)
}

pub fn extend_cluster_chain(
    fs: &Fat32,
    start_cluster: u32,
    additional_count: u32,
    read_fn: fn(u8, u64, &mut [u8]) -> BlockResult<()>,
    write_fn: fn(u8, u64, &[u8]) -> BlockResult<()>,
) -> BlockResult<Option<u32>> {
    if additional_count == 0 {
        return Ok(None);
    }

    let mut last_cluster = start_cluster;
    while !is_eof(read_fat_entry(fs, last_cluster, read_fn)?) {
        last_cluster = read_fat_entry(fs, last_cluster, read_fn)?;
    }

    let new_chain_start = allocate_cluster_chain(fs, additional_count, read_fn, write_fn)?;

    if let Some(first_new) = new_chain_start {
        write_fat_entry(fs, last_cluster, first_new, read_fn, write_fn)?;
    }

    Ok(new_chain_start)
}

pub fn truncate_cluster_chain(
    fs: &Fat32,
    start_cluster: u32,
    keep_count: u32,
    read_fn: fn(u8, u64, &mut [u8]) -> BlockResult<()>,
    write_fn: fn(u8, u64, &[u8]) -> BlockResult<()>,
) -> BlockResult<u32> {
    if start_cluster < 2 || is_free_cluster(start_cluster) {
        return Ok(0);
    }

    if keep_count == 0 {
        return free_cluster_chain(fs, start_cluster, read_fn, write_fn);
    }

    let mut cluster = start_cluster;
    for _ in 1..keep_count {
        let next = read_fat_entry(fs, cluster, read_fn)?;
        if is_eof(next) || is_free_cluster(next) {
            return Ok(0);
        }
        cluster = next;
    }

    let next_to_free = read_fat_entry(fs, cluster, read_fn)?;
    write_fat_entry(fs, cluster, FAT32_EOC, read_fn, write_fn)?;

    if !is_eof(next_to_free) && !is_free_cluster(next_to_free) {
        return free_cluster_chain(fs, next_to_free, read_fn, write_fn);
    }

    Ok(0)
}
