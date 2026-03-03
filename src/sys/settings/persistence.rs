// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Settings persistence to FAT32 filesystem

use core::sync::atomic::Ordering;
use crate::storage::block::{BlockDeviceType, BlockError, BlockResult, get_device};
use super::types::Settings;
use super::state::{CURRENT_SETTINGS, SETTINGS_LOADED, SETTINGS_MODIFIED};
use super::serialize::{serialize, deserialize};

pub const SETTINGS_FILENAME: &[u8] = b"SETTINGS.CFG";

fn block_read(device_id: u8, sector: u64, buffer: &mut [u8]) -> BlockResult<()> {
    let dev = get_device(device_id).ok_or(BlockError::InvalidDevice)?;

    match dev.device_type {
        BlockDeviceType::UsbMassStorage => {
            crate::storage::usb_msc::read_blocks(device_id, sector, 1, buffer)
        }
        BlockDeviceType::SataAhci => Err(BlockError::NotReady),
        BlockDeviceType::Nvme => Err(BlockError::NotReady),
        BlockDeviceType::Unknown => Err(BlockError::InvalidDevice),
    }
}

fn block_write(device_id: u8, sector: u64, buffer: &[u8]) -> BlockResult<()> {
    let dev = get_device(device_id).ok_or(BlockError::InvalidDevice)?;

    if dev.read_only {
        return Err(BlockError::ReadOnly);
    }

    match dev.device_type {
        BlockDeviceType::UsbMassStorage => {
            crate::storage::usb_msc::write_blocks(device_id, sector, 1, buffer)
        }
        BlockDeviceType::SataAhci => Err(BlockError::NotReady),
        BlockDeviceType::Nvme => Err(BlockError::NotReady),
        BlockDeviceType::Unknown => Err(BlockError::InvalidDevice),
    }
}

pub fn save_to_disk() -> bool {
    use crate::storage::fat32;

    if fat32::fs_count() == 0 {
        return false;
    }

    let fs = match fat32::get_fs(0) {
        Some(f) => f,
        None => return false,
    };

    let settings = unsafe { CURRENT_SETTINGS };
    let mut buf = [0u8; 1024];
    let len = serialize(&settings, &mut buf);

    match fat32::find_file(&fs, SETTINGS_FILENAME, block_read) {
        Ok(Some(mut entry)) => {
            match fat32::update_file(&fs, &mut entry, fs.root_cluster, &buf[..len], block_read, block_write) {
                Ok(_) => {
                    SETTINGS_MODIFIED.store(false, Ordering::SeqCst);
                    true
                }
                Err(_) => {
                    let _ = fat32::delete_file(&fs, SETTINGS_FILENAME, block_read, block_write);
                    match fat32::create_file(&fs, fs.root_cluster, SETTINGS_FILENAME, &buf[..len], block_read, block_write) {
                        Ok(_) => {
                            SETTINGS_MODIFIED.store(false, Ordering::SeqCst);
                            true
                        }
                        Err(_) => false,
                    }
                }
            }
        }
        Ok(None) => {
            match fat32::create_file(&fs, fs.root_cluster, SETTINGS_FILENAME, &buf[..len], block_read, block_write) {
                Ok(_) => {
                    SETTINGS_MODIFIED.store(false, Ordering::SeqCst);
                    true
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

pub fn load_from_disk() -> bool {
    use crate::storage::fat32;

    if fat32::fs_count() == 0 {
        return false;
    }

    let fs = match fat32::get_fs(0) {
        Some(f) => f,
        None => return false,
    };

    let entry = match fat32::find_file(&fs, SETTINGS_FILENAME, block_read) {
        Ok(Some(e)) => e,
        Ok(None) => return false,
        Err(_) => return false,
    };

    let mut buf = [0u8; 1024];
    let bytes_read = match fat32::read_file(&fs, &entry, &mut buf, block_read) {
        Ok(n) => n,
        Err(_) => return false,
    };

    if bytes_read == 0 {
        return false;
    }

    let mut settings = Settings::default();
    deserialize(&buf[..bytes_read], &mut settings);

    unsafe {
        CURRENT_SETTINGS = settings;
    }
    SETTINGS_LOADED.store(true, Ordering::SeqCst);
    SETTINGS_MODIFIED.store(false, Ordering::SeqCst);

    true
}
