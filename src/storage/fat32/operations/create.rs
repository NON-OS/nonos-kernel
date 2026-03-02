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

use crate::storage::block::{BlockError, BlockResult};
use super::super::types::*;
use super::super::state::{serial_print, serial_println, serial_print_dec, SECTOR_BUFFER};
use super::cluster::{is_eof, read_fat_entry, allocate_cluster_chain, free_cluster_chain, extend_cluster_chain, truncate_cluster_chain};
use super::write::write_cluster;
use super::dir::{make_dir_entry, find_free_dir_slot, update_dir_entry};

pub fn create_file(
    fs: &Fat32,
    dir_cluster: u32,
    name: &[u8],
    data: &[u8],
    read_fn: fn(u8, u64, &mut [u8]) -> BlockResult<()>,
    write_fn: fn(u8, u64, &[u8]) -> BlockResult<()>,
) -> BlockResult<()> {
    serial_print(b"[FAT32] Creating file: ");
    serial_print(name);
    serial_println(b"");

    let clusters_needed = if data.is_empty() {
        0
    } else {
        ((data.len() as u32) + fs.cluster_size - 1) / fs.cluster_size
    };

    let first_cluster = if clusters_needed > 0 {
        match allocate_cluster_chain(fs, clusters_needed, read_fn, write_fn)? {
            Some(c) => c,
            None => {
                serial_println(b"[FAT32] ERROR: No space for file data");
                return Err(BlockError::IoError);
            }
        }
    } else {
        0
    };

    if clusters_needed > 0 {
        let mut current_cluster = first_cluster;
        let mut offset = 0usize;

        while offset < data.len() && !is_eof(current_cluster) {
            let chunk_len = (data.len() - offset).min(fs.cluster_size as usize);
            write_cluster(fs, current_cluster, &data[offset..offset + chunk_len], write_fn)?;
            offset += chunk_len;

            if offset < data.len() {
                current_cluster = read_fat_entry(fs, current_cluster, read_fn)?;
            }
        }
    }

    let (_cluster, slot_sector, slot_offset) = match find_free_dir_slot(fs, dir_cluster, read_fn)? {
        Some(s) => s,
        None => {
            serial_println(b"[FAT32] ERROR: No free directory slot");
            return Err(BlockError::IoError);
        }
    };

    let entry = make_dir_entry(name, false, first_cluster, data.len() as u32);

    // SAFETY: SECTOR_BUFFER is a kernel-internal buffer for FAT32 I/O
    let sector_buf = unsafe { &mut SECTOR_BUFFER[..fs.bytes_per_sector as usize] };
    read_fn(fs.device_id, slot_sector as u64, sector_buf)?;

    // SAFETY: DirEntry is repr(C) with known size DIR_ENTRY_SIZE
    let entry_bytes = unsafe {
        core::slice::from_raw_parts(&entry as *const DirEntry as *const u8, DIR_ENTRY_SIZE)
    };
    sector_buf[slot_offset..slot_offset + DIR_ENTRY_SIZE].copy_from_slice(entry_bytes);

    write_fn(fs.device_id, slot_sector as u64, sector_buf)?;

    serial_print(b"[FAT32] File created, ");
    serial_print_dec(data.len() as u64);
    serial_print(b" bytes, cluster ");
    serial_print_dec(first_cluster as u64);
    serial_println(b"");

    Ok(())
}

pub fn update_file(
    fs: &Fat32,
    entry: &mut DirEntry,
    dir_cluster: u32,
    data: &[u8],
    read_fn: fn(u8, u64, &mut [u8]) -> BlockResult<()>,
    write_fn: fn(u8, u64, &[u8]) -> BlockResult<()>,
) -> BlockResult<()> {
    let old_clusters = if entry.file_size == 0 {
        0
    } else {
        ((entry.file_size as usize) + fs.cluster_size as usize - 1) / fs.cluster_size as usize
    };

    let new_clusters = if data.is_empty() {
        0
    } else {
        (data.len() + fs.cluster_size as usize - 1) / fs.cluster_size as usize
    };

    serial_print(b"[FAT32] Updating file: old_clusters=");
    serial_print_dec(old_clusters as u64);
    serial_print(b", new_clusters=");
    serial_print_dec(new_clusters as u64);
    serial_println(b"");

    let first_cluster;

    if data.is_empty() {
        if entry.first_cluster() != 0 {
            free_cluster_chain(fs, entry.first_cluster(), read_fn, write_fn)?;
        }
        first_cluster = 0;
    } else if entry.first_cluster() == 0 || old_clusters == 0 {
        match allocate_cluster_chain(fs, new_clusters as u32, read_fn, write_fn)? {
            Some(c) => first_cluster = c,
            None => {
                serial_println(b"[FAT32] ERROR: No space for file data");
                return Err(BlockError::IoError);
            }
        }
    } else if new_clusters <= old_clusters {
        first_cluster = entry.first_cluster();
        if new_clusters < old_clusters {
            truncate_cluster_chain(fs, first_cluster, new_clusters as u32, read_fn, write_fn)?;
        }
    } else {
        first_cluster = entry.first_cluster();
        let additional = (new_clusters - old_clusters) as u32;
        extend_cluster_chain(fs, first_cluster, additional, read_fn, write_fn)?;
    }

    if !data.is_empty() && first_cluster != 0 {
        let mut current_cluster = first_cluster;
        let mut offset = 0usize;

        while offset < data.len() && !is_eof(current_cluster) {
            let chunk_len = (data.len() - offset).min(fs.cluster_size as usize);
            write_cluster(fs, current_cluster, &data[offset..offset + chunk_len], write_fn)?;
            offset += chunk_len;

            if offset < data.len() {
                current_cluster = read_fat_entry(fs, current_cluster, read_fn)?;
            }
        }
    }

    entry.first_cluster_hi = (first_cluster >> 16) as u16;
    entry.first_cluster_lo = first_cluster as u16;
    entry.file_size = data.len() as u32;

    update_dir_entry(fs, dir_cluster, entry, read_fn, write_fn)?;

    serial_print(b"[FAT32] File updated, new size=");
    serial_print_dec(data.len() as u64);
    serial_println(b" bytes");

    Ok(())
}
