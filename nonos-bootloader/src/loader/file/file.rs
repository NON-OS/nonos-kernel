// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use uefi::prelude::*;
use uefi::proto::media::file::{File, FileAttribute, FileMode, FileType, RegularFile};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::MemoryType;
use uefi::CStr16;

use crate::log::logger::{log_error, log_info};

const MAX_KERNEL_SIZE: usize = 64 * 1024 * 1024;

#[derive(Debug)]
pub enum FileLoadError {
    NoFilesystem,
    OpenVolumeFailed,
    FileNotFound,
    OpenFailed,
    InfoFailed,
    TooLarge,
    AllocationFailed,
    ReadFailed,
    NotRegularFile,
}

pub type FileResult<T> = Result<T, FileLoadError>;

pub fn load_file_from_esp(system_table: &SystemTable<Boot>, path: &CStr16) -> FileResult<Vec<u8>> {
    let bs = system_table.boot_services();

    let handles = bs
        .find_handles::<SimpleFileSystem>()
        .map_err(|_| FileLoadError::NoFilesystem)?;

    if handles.is_empty() {
        log_error("file", "No filesystem handles found");
        return Err(FileLoadError::NoFilesystem);
    }

    for &handle in handles.iter() {
        if let Ok(mut fs) = bs.open_protocol_exclusive::<SimpleFileSystem>(handle) {
            if let Ok(mut root) = fs.open_volume() {
                match root.open(path, FileMode::Read, FileAttribute::empty()) {
                    Ok(file_handle) => {
                        let file_type = file_handle.into_type().map_err(|_| {
                            log_error("file", "Failed to determine file type");
                            FileLoadError::NotRegularFile
                        })?;

                        if let FileType::Regular(mut regular_file) = file_type {
                            return read_regular_file(&mut regular_file, bs);
                        } else {
                            log_error("file", "Path is not a regular file");
                            return Err(FileLoadError::NotRegularFile);
                        }
                    }
                    Err(_) => {
                        continue;
                    }
                }
            }
        }
    }

    log_error("file", "File not found on any volume");
    Err(FileLoadError::FileNotFound)
}

fn read_regular_file(
    file: &mut RegularFile,
    bs: &uefi::table::boot::BootServices,
) -> FileResult<Vec<u8>> {
    let mut info_buf = [0u8; 256];

    let file_size = match file.get_info::<uefi::proto::media::file::FileInfo>(&mut info_buf) {
        Ok(info) => info.file_size() as usize,
        Err(_) => {
            log_info("file", "Could not get file info, reading in chunks");
            return read_file_chunked(file, bs);
        }
    };

    if file_size > MAX_KERNEL_SIZE {
        log_error("file", "File exceeds maximum size");
        return Err(FileLoadError::TooLarge);
    }

    if file_size == 0 {
        log_info("file", "File is empty");
        return Ok(Vec::new());
    }

    let pages = (file_size + 4095) / 4096;
    let buffer_addr = bs
        .allocate_pages(
            uefi::table::boot::AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            pages,
        )
        .map_err(|_| {
            log_error("file", "Failed to allocate buffer for file");
            FileLoadError::AllocationFailed
        })?;

    // ## SAFETY: buffer_addr points to pages*4096 bytes of valid memory
    let buffer = unsafe { core::slice::from_raw_parts_mut(buffer_addr as *mut u8, file_size) };

    let bytes_read = file.read(buffer).map_err(|_| {
        let _ = bs.free_pages(buffer_addr, pages);
        log_error("file", "Failed to read file contents");
        FileLoadError::ReadFailed
    })?;

    let mut result = Vec::with_capacity(bytes_read);
    result.extend_from_slice(&buffer[..bytes_read]);

    let _ = bs.free_pages(buffer_addr, pages);

    log_info("file", "File loaded successfully");
    Ok(result)
}

fn read_file_chunked(
    file: &mut RegularFile,
    _bs: &uefi::table::boot::BootServices,
) -> FileResult<Vec<u8>> {
    const CHUNK_SIZE: usize = 64 * 1024;
    let mut result = Vec::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total_read = 0usize;

    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                total_read += n;
                if total_read > MAX_KERNEL_SIZE {
                    log_error("file", "File exceeds maximum size during chunked read");
                    return Err(FileLoadError::TooLarge);
                }
                result.extend_from_slice(&buffer[..n]);
            }
            Err(_) => {
                log_error("file", "Read error during chunked read");
                return Err(FileLoadError::ReadFailed);
            }
        }
    }

    Ok(result)
}

pub fn load_kernel_binary(system_table: &SystemTable<Boot>) -> FileResult<Vec<u8>> {
    log_info("file", "Searching for kernel binary...");

    log_info("file", "Trying \\EFI\\nonos\\kernel.bin");
    if let Ok(data) = load_file_from_esp(system_table, uefi::cstr16!("\\EFI\\nonos\\kernel.bin")) {
        log_info("file", "Kernel found and loaded");
        return Ok(data);
    }

    log_info("file", "Trying \\EFI\\nonos\\nonos_kernel");
    if let Ok(data) = load_file_from_esp(system_table, uefi::cstr16!("\\EFI\\nonos\\nonos_kernel"))
    {
        log_info("file", "Kernel found and loaded");
        return Ok(data);
    }

    log_info("file", "Trying \\nonos_kernel");
    if let Ok(data) = load_file_from_esp(system_table, uefi::cstr16!("\\nonos_kernel")) {
        log_info("file", "Kernel found and loaded");
        return Ok(data);
    }

    log_info("file", "Trying \\kernel.bin");
    if let Ok(data) = load_file_from_esp(system_table, uefi::cstr16!("\\kernel.bin")) {
        log_info("file", "Kernel found and loaded");
        return Ok(data);
    }

    log_error("file", "Kernel not found at any expected path");
    Err(FileLoadError::FileNotFound)
}

pub fn file_exists(system_table: &SystemTable<Boot>, path: &CStr16) -> bool {
    let bs = system_table.boot_services();
    if let Ok(handles) = bs.find_handles::<SimpleFileSystem>() {
        for &handle in handles.iter() {
            if let Ok(mut fs) = bs.open_protocol_exclusive::<SimpleFileSystem>(handle) {
                if let Ok(mut root) = fs.open_volume() {
                    if root
                        .open(path, FileMode::Read, FileAttribute::empty())
                        .is_ok()
                    {
                        return true;
                    }
                }
            }
        }
    }
    false
}
