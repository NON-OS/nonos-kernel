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
use super::super::state::SECTOR_BUFFER;
use super::cluster::{is_eof, read_fat_entry};

pub fn make_dir_entry(name: &[u8], is_dir: bool, first_cluster: u32, file_size: u32) -> DirEntry {
    let mut entry = DirEntry {
        name: [b' '; 8],
        ext: [b' '; 3],
        attr: if is_dir { ATTR_DIRECTORY } else { ATTR_ARCHIVE },
        nt_reserved: 0,
        create_time_tenth: 0,
        create_time: 0,
        create_date: 0,
        access_date: 0,
        first_cluster_hi: (first_cluster >> 16) as u16,
        write_time: 0,
        write_date: 0,
        first_cluster_lo: first_cluster as u16,
        file_size,
    };

    let mut name_idx = 0usize;
    let mut ext_idx = 0usize;
    let mut in_ext = false;

    for &ch in name {
        let upper = if ch >= b'a' && ch <= b'z' { ch - 32 } else { ch };

        if ch == b'.' && !in_ext {
            in_ext = true;
        } else if !in_ext && name_idx < 8 {
            entry.name[name_idx] = upper;
            name_idx += 1;
        } else if in_ext && ext_idx < 3 {
            entry.ext[ext_idx] = upper;
            ext_idx += 1;
        }
    }

    entry
}

pub fn find_free_dir_slot(
    fs: &Fat32,
    dir_cluster: u32,
    read_fn: fn(u8, u64, &mut [u8]) -> BlockResult<()>,
) -> BlockResult<Option<(u32, u32, usize)>> {
    let mut current_cluster = dir_cluster;

    while !is_eof(current_cluster) {
        let start_sector = fs.cluster_to_sector(current_cluster);

        for s in 0..fs.sectors_per_cluster {
            let sector = start_sector + s as u32;
            // SAFETY: SECTOR_BUFFER is a kernel-internal buffer for FAT32 I/O.
            let sector_buf = unsafe { &mut SECTOR_BUFFER[..fs.bytes_per_sector as usize] };
            read_fn(fs.device_id, sector as u64, sector_buf)?;

            let entries_per_sector = fs.bytes_per_sector as usize / DIR_ENTRY_SIZE;
            for i in 0..entries_per_sector {
                let offset = i * DIR_ENTRY_SIZE;
                // SAFETY: DirEntry is repr(C) and buffer contains valid directory data.
                let entry = unsafe { &*(sector_buf[offset..].as_ptr() as *const DirEntry) };

                if entry.is_free() || entry.is_end() {
                    return Ok(Some((current_cluster, sector, offset)));
                }
            }
        }

        current_cluster = read_fat_entry(fs, current_cluster, read_fn)?;
    }

    Ok(None)
}

pub fn update_dir_entry(
    fs: &Fat32,
    dir_cluster: u32,
    entry: &DirEntry,
    read_fn: fn(u8, u64, &mut [u8]) -> BlockResult<()>,
    write_fn: fn(u8, u64, &[u8]) -> BlockResult<()>,
) -> BlockResult<()> {
    use crate::storage::block::BlockError;

    let mut current_cluster = dir_cluster;

    while !is_eof(current_cluster) {
        let start_sector = fs.cluster_to_sector(current_cluster);

        for s in 0..fs.sectors_per_cluster {
            let sector = start_sector + s as u32;
            // SAFETY: SECTOR_BUFFER is a kernel-internal buffer for FAT32 I/O.
            let sector_buf = unsafe { &mut SECTOR_BUFFER[..fs.bytes_per_sector as usize] };
            read_fn(fs.device_id, sector as u64, sector_buf)?;

            let entries_per_sector = fs.bytes_per_sector as usize / DIR_ENTRY_SIZE;
            for i in 0..entries_per_sector {
                let offset = i * DIR_ENTRY_SIZE;
                // SAFETY: DirEntry is repr(C) and buffer contains valid directory data.
                let disk_entry = unsafe { &*(sector_buf[offset..].as_ptr() as *const DirEntry) };

                if disk_entry.is_end() {
                    return Err(BlockError::IoError);
                }

                if disk_entry.is_free() || disk_entry.is_long_name() {
                    continue;
                }

                if disk_entry.name == entry.name && disk_entry.ext == entry.ext {
                    // SAFETY: DirEntry is repr(C) with known size DIR_ENTRY_SIZE.
                    let entry_bytes = unsafe {
                        core::slice::from_raw_parts(entry as *const DirEntry as *const u8, DIR_ENTRY_SIZE)
                    };
                    sector_buf[offset..offset + DIR_ENTRY_SIZE].copy_from_slice(entry_bytes);
                    write_fn(fs.device_id, sector as u64, sector_buf)?;
                    return Ok(());
                }
            }
        }

        current_cluster = read_fat_entry(fs, current_cluster, read_fn)?;
    }

    Err(BlockError::IoError)
}
