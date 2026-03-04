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

use core::sync::atomic::Ordering;
use crate::fs::ramfs;
use crate::storage::fat32;
use crate::storage::block::{BlockDeviceType, BlockError, BlockResult, get_device as block_get_device};
use super::state::*;
use super::buffer;

fn is_disk_path(path: &str) -> bool {
    path.starts_with("/disk/")
}

fn parse_disk_path(path: &str) -> Option<(u8, &str)> {
    if !path.starts_with("/disk/") {
        return None;
    }

    let rest = &path[6..];
    let slash_pos = rest.find('/')?;
    let fs_id_str = &rest[..slash_pos];
    let filename = &rest[slash_pos + 1..];

    let fs_id: u8 = fs_id_str.parse().ok()?;

    if filename.is_empty() {
        return None;
    }

    Some((fs_id, filename))
}

fn block_read(device_id: u8, sector: u64, buffer: &mut [u8]) -> BlockResult<()> {
    let dev = block_get_device(device_id).ok_or(BlockError::InvalidDevice)?;

    match dev.device_type {
        BlockDeviceType::UsbMassStorage => {
            crate::storage::usb_msc::read_blocks(device_id, sector, 1, buffer)
        }
        BlockDeviceType::SataAhci | BlockDeviceType::Nvme => {
            Err(BlockError::NotReady)
        }
        BlockDeviceType::Unknown => Err(BlockError::InvalidDevice),
    }
}

fn block_write(device_id: u8, sector: u64, buffer: &[u8]) -> BlockResult<()> {
    let dev = block_get_device(device_id).ok_or(BlockError::InvalidDevice)?;

    if dev.read_only {
        return Err(BlockError::ReadOnly);
    }

    match dev.device_type {
        BlockDeviceType::UsbMassStorage => {
            crate::storage::usb_msc::write_blocks(device_id, sector, 1, buffer)
        }
        BlockDeviceType::SataAhci | BlockDeviceType::Nvme => {
            Err(BlockError::NotReady)
        }
        BlockDeviceType::Unknown => Err(BlockError::InvalidDevice),
    }
}

pub(super) fn new_file() {
    reset_state();
    EDITOR_STATUS.store(STATUS_NEW, Ordering::Relaxed);
}

pub(super) fn open_file(path: &str) -> bool {
    if is_disk_path(path) {
        open_file_fat32(path)
    } else {
        open_file_ramfs(path)
    }
}

fn open_file_ramfs(path: &str) -> bool {
    match ramfs::read_file(path) {
        Ok(data) => {
            buffer::load_content(&data);
            set_path(path);
            EDITOR_MODIFIED.store(false, Ordering::Relaxed);
            EDITOR_STATUS.store(STATUS_OPENED, Ordering::Relaxed);
            true
        }
        Err(_) => {
            EDITOR_STATUS.store(STATUS_ERROR, Ordering::Relaxed);
            false
        }
    }
}

fn open_file_fat32(path: &str) -> bool {
    let (fs_id, filename) = match parse_disk_path(path) {
        Some(p) => p,
        None => {
            EDITOR_STATUS.store(STATUS_ERROR, Ordering::Relaxed);
            return false;
        }
    };

    let fs = match fat32::get_fs(fs_id) {
        Some(f) => f,
        None => {
            EDITOR_STATUS.store(STATUS_ERROR, Ordering::Relaxed);
            return false;
        }
    };

    let entry = match fat32::find_file(&fs, filename.as_bytes(), block_read) {
        Ok(Some(e)) => e,
        Ok(None) | Err(_) => {
            EDITOR_STATUS.store(STATUS_ERROR, Ordering::Relaxed);
            return false;
        }
    };

    let mut read_buf = [0u8; BUFFER_SIZE];
    let bytes_read = match fat32::read_file(&fs, &entry, &mut read_buf, block_read) {
        Ok(n) => n,
        Err(_) => {
            EDITOR_STATUS.store(STATUS_ERROR, Ordering::Relaxed);
            return false;
        }
    };

    buffer::load_content(&read_buf[..bytes_read]);
    set_path(path);
    EDITOR_MODIFIED.store(false, Ordering::Relaxed);
    EDITOR_STATUS.store(STATUS_OPENED, Ordering::Relaxed);
    true
}

pub(super) fn save_file() -> bool {
    let path = match get_path() {
        Some(p) if !p.is_empty() => p,
        _ => {
            EDITOR_STATUS.store(STATUS_ERROR, Ordering::Relaxed);
            return false;
        }
    };

    if is_disk_path(path) {
        save_file_fat32(path)
    } else {
        save_file_ramfs(path)
    }
}

fn save_file_ramfs(path: &str) -> bool {
    let data = get_buffer_slice();

    let result = if ramfs::exists(path) {
        ramfs::write_file(path, data)
    } else {
        ramfs::create_file(path, data)
    };

    match result {
        Ok(()) => {
            EDITOR_MODIFIED.store(false, Ordering::Relaxed);
            EDITOR_STATUS.store(STATUS_SAVED, Ordering::Relaxed);
            true
        }
        Err(_) => {
            EDITOR_STATUS.store(STATUS_ERROR, Ordering::Relaxed);
            false
        }
    }
}

fn save_file_fat32(path: &str) -> bool {
    let (fs_id, filename) = match parse_disk_path(path) {
        Some(p) => p,
        None => {
            EDITOR_STATUS.store(STATUS_ERROR, Ordering::Relaxed);
            return false;
        }
    };

    let fs = match fat32::get_fs(fs_id) {
        Some(f) => f,
        None => {
            EDITOR_STATUS.store(STATUS_ERROR, Ordering::Relaxed);
            return false;
        }
    };

    let data = get_buffer_slice();

    match fat32::find_file(&fs, filename.as_bytes(), block_read) {
        Ok(Some(mut entry)) => {
            match fat32::update_file(&fs, &mut entry, fs.root_cluster, data, block_read, block_write) {
                Ok(_) => {
                    EDITOR_MODIFIED.store(false, Ordering::Relaxed);
                    EDITOR_STATUS.store(STATUS_SAVED, Ordering::Relaxed);
                    true
                }
                Err(_) => {
                    let _ = fat32::delete_file(&fs, filename.as_bytes(), block_read, block_write);
                    match fat32::create_file(&fs, fs.root_cluster, filename.as_bytes(), data, block_read, block_write) {
                        Ok(_) => {
                            EDITOR_MODIFIED.store(false, Ordering::Relaxed);
                            EDITOR_STATUS.store(STATUS_SAVED, Ordering::Relaxed);
                            true
                        }
                        Err(_) => {
                            EDITOR_STATUS.store(STATUS_ERROR, Ordering::Relaxed);
                            false
                        }
                    }
                }
            }
        }
        Ok(None) => {
            match fat32::create_file(&fs, fs.root_cluster, filename.as_bytes(), data, block_read, block_write) {
                Ok(_) => {
                    EDITOR_MODIFIED.store(false, Ordering::Relaxed);
                    EDITOR_STATUS.store(STATUS_SAVED, Ordering::Relaxed);
                    true
                }
                Err(_) => {
                    EDITOR_STATUS.store(STATUS_ERROR, Ordering::Relaxed);
                    false
                }
            }
        }
        Err(_) => {
            EDITOR_STATUS.store(STATUS_ERROR, Ordering::Relaxed);
            false
        }
    }
}

pub(super) fn save_file_as(path: &str) -> bool {
    set_path(path);
    save_file()
}

pub(super) fn close_file() {
    reset_state();
}

pub(super) fn is_modified() -> bool {
    EDITOR_MODIFIED.load(Ordering::Relaxed)
}

pub(super) fn has_file() -> bool {
    EDITOR_PATH_LEN.load(Ordering::Relaxed) > 0
}
