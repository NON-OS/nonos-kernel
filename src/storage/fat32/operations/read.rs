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
use super::super::{serial_print, serial_println, serial_print_dec, SECTOR_BUFFER};
use super::cluster::{is_eof, read_fat_entry};

pub fn read_directory(
    fs: &Fat32,
    cluster: u32,
    read_fn: fn(u8, u64, &mut [u8]) -> BlockResult<()>,
    callback: fn(&DirEntry) -> bool,
) -> BlockResult<()> {
    let mut current_cluster = cluster;

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
                // SAFETY: DirEntry is repr(C) and the buffer contains valid directory data.
                let entry = unsafe { &*(sector_buf[offset..].as_ptr() as *const DirEntry) };

                if entry.is_end() {
                    return Ok(());
                }

                if entry.is_free() {
                    continue;
                }

                if entry.is_long_name() {
                    continue;
                }

                if entry.is_volume_label() {
                    continue;
                }

                if !callback(entry) {
                    return Ok(());
                }
            }
        }

        current_cluster = read_fat_entry(fs, current_cluster, read_fn)?;
    }

    Ok(())
}

pub fn find_file(
    fs: &Fat32,
    name: &[u8],
    read_fn: fn(u8, u64, &mut [u8]) -> BlockResult<()>,
) -> BlockResult<Option<DirEntry>> {
    static mut SEARCH_NAME: [u8; 13] = [0u8; 13];
    static mut SEARCH_LEN: usize = 0;
    static mut FOUND_ENTRY: Option<DirEntry> = None;

    // SAFETY: Single-threaded kernel operation for file search.
    unsafe {
        SEARCH_LEN = name.len().min(13);
        SEARCH_NAME[..SEARCH_LEN].copy_from_slice(&name[..SEARCH_LEN]);
        FOUND_ENTRY = None;
    }

    fn find_callback(entry: &DirEntry) -> bool {
        // SAFETY: Accessing statics set before this callback is invoked.
        unsafe {
            if entry.name_matches(&SEARCH_NAME[..SEARCH_LEN]) {
                FOUND_ENTRY = Some(*entry);
                return false;
            }
        }
        true
    }

    read_directory(fs, fs.root_cluster, read_fn, find_callback)?;

    // SAFETY: FOUND_ENTRY set by callback during read_directory.
    let result = unsafe { FOUND_ENTRY };

    Ok(result)
}

pub fn read_file(
    fs: &Fat32,
    entry: &DirEntry,
    buffer: &mut [u8],
    read_fn: fn(u8, u64, &mut [u8]) -> BlockResult<()>,
) -> BlockResult<usize> {
    let file_size = entry.file_size as usize;
    let read_size = file_size.min(buffer.len());

    if read_size == 0 {
        return Ok(0);
    }

    let mut current_cluster = entry.first_cluster();
    let mut bytes_read = 0;

    while bytes_read < read_size && !is_eof(current_cluster) {
        let start_sector = fs.cluster_to_sector(current_cluster);

        for s in 0..fs.sectors_per_cluster {
            if bytes_read >= read_size {
                break;
            }

            let sector = start_sector + s as u32;
            // SAFETY: SECTOR_BUFFER is a kernel-internal buffer for FAT32 I/O.
            let sector_buf = unsafe { &mut SECTOR_BUFFER[..fs.bytes_per_sector as usize] };
            read_fn(fs.device_id, sector as u64, sector_buf)?;

            let copy_size = (read_size - bytes_read).min(fs.bytes_per_sector as usize);
            buffer[bytes_read..bytes_read + copy_size].copy_from_slice(&sector_buf[..copy_size]);
            bytes_read += copy_size;
        }

        if bytes_read < read_size {
            current_cluster = read_fat_entry(fs, current_cluster, read_fn)?;
        }
    }

    Ok(bytes_read)
}

pub fn list_directory(
    fs: &Fat32,
    cluster: u32,
    read_fn: fn(u8, u64, &mut [u8]) -> BlockResult<()>,
) -> BlockResult<()> {
    fn print_entry(entry: &DirEntry) -> bool {
        let mut name_buf = [0u8; 13];
        let len = entry.get_short_name(&mut name_buf);

        if entry.is_directory() {
            serial_print(b"<DIR>  ");
        } else {
            serial_print(b"       ");
        }

        if !entry.is_directory() {
            serial_print_dec(entry.file_size as u64);
            serial_print(b"  ");
        } else {
            serial_print(b"          ");
        }

        serial_print(&name_buf[..len]);
        serial_println(b"");

        true
    }

    serial_println(b"Directory listing:");
    serial_println(b"------------------");
    read_directory(fs, cluster, read_fn, print_entry)?;
    serial_println(b"------------------");

    Ok(())
}
