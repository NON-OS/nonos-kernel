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
use super::super::state::{serial_print, serial_println, SECTOR_BUFFER};
use super::cluster::{is_eof, read_fat_entry, write_fat_entry, is_free_cluster};
use super::read::find_file;

pub fn rename_file(
    fs: &Fat32,
    old_name: &[u8],
    new_name: &[u8],
    read_fn: fn(u8, u64, &mut [u8]) -> BlockResult<()>,
    write_fn: fn(u8, u64, &[u8]) -> BlockResult<()>,
) -> BlockResult<()> {
    serial_print(b"[FAT32] Renaming ");
    serial_print(old_name);
    serial_print(b" -> ");
    serial_print(new_name);
    serial_println(b"");

    let mut new_entry_name = [b' '; 8];
    let mut new_entry_ext = [b' '; 3];
    let mut name_idx = 0usize;
    let mut ext_idx = 0usize;
    let mut in_ext = false;

    for &ch in new_name {
        let upper = if ch >= b'a' && ch <= b'z' { ch - 32 } else { ch };

        if ch == b'.' && !in_ext {
            in_ext = true;
        } else if !in_ext && name_idx < 8 {
            new_entry_name[name_idx] = upper;
            name_idx += 1;
        } else if in_ext && ext_idx < 3 {
            new_entry_ext[ext_idx] = upper;
            ext_idx += 1;
        }
    }

    let mut current_cluster = fs.root_cluster;

    while !is_eof(current_cluster) {
        let start_sector = fs.cluster_to_sector(current_cluster);

        for s in 0..fs.sectors_per_cluster {
            let sector = start_sector + s as u32;
            // SAFETY: SECTOR_BUFFER is a kernel-internal buffer for FAT32 I/O
            let sector_buf = unsafe { &mut SECTOR_BUFFER[..fs.bytes_per_sector as usize] };
            read_fn(fs.device_id, sector as u64, sector_buf)?;

            let entries_per_sector = fs.bytes_per_sector as usize / DIR_ENTRY_SIZE;
            for i in 0..entries_per_sector {
                let offset = i * DIR_ENTRY_SIZE;
                // SAFETY: DirEntry is repr(C) and buffer contains valid directory data
                let entry = unsafe { &mut *(sector_buf[offset..].as_mut_ptr() as *mut DirEntry) };

                if entry.is_end() {
                    serial_println(b"[FAT32] File not found for rename");
                    return Err(BlockError::IoError);
                }

                if entry.is_free() || entry.is_long_name() || entry.is_volume_label() {
                    continue;
                }

                if entry.name_matches(old_name) {
                    entry.name = new_entry_name;
                    entry.ext = new_entry_ext;

                    write_fn(fs.device_id, sector as u64, sector_buf)?;

                    serial_println(b"[FAT32] Rename complete");
                    return Ok(());
                }
            }
        }

        current_cluster = read_fat_entry(fs, current_cluster, read_fn)?;
    }

    serial_println(b"[FAT32] File not found for rename");
    Err(BlockError::IoError)
}

pub fn delete_file(
    fs: &Fat32,
    name: &[u8],
    read_fn: fn(u8, u64, &mut [u8]) -> BlockResult<()>,
    write_fn: fn(u8, u64, &[u8]) -> BlockResult<()>,
) -> BlockResult<()> {
    let entry = match find_file(fs, name, read_fn)? {
        Some(e) => e,
        None => {
            serial_println(b"[FAT32] File not found");
            return Err(BlockError::IoError);
        }
    };

    if entry.first_cluster() != 0 {
        let mut cluster = entry.first_cluster();
        while !is_eof(cluster) && !is_free_cluster(cluster) {
            let next = read_fat_entry(fs, cluster, read_fn)?;
            write_fat_entry(fs, cluster, FAT32_FREE, read_fn, write_fn)?;
            cluster = next;
        }
    }

    serial_println(b"[FAT32] File clusters freed");

    Ok(())
}
