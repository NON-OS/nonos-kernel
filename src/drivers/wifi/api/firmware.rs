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

use super::super::error::WifiError;
use super::init::{get_device, get_realtek_device, is_available, is_realtek};
use crate::storage::fat32;
use crate::storage::block::{BlockDeviceType, BlockError, BlockResult, get_device as block_get_device};

pub fn try_load_firmware() -> Result<(), WifiError> {
    if !is_available() {
        return Err(WifiError::NotInitialized);
    }

    for fs_id in 0..8 {
        match load_firmware_from_disk(fs_id) {
            Ok(()) => {
                crate::log::info!("wifi: Firmware loaded from filesystem {}", fs_id);
                return Ok(());
            }
            Err(WifiError::FirmwareNotFound) => continue,
            Err(e) => {
                crate::log_warn!("wifi: Firmware load error on fs {}: {:?}", fs_id, e);
            }
        }
    }

    Err(WifiError::FirmwareNotFound)
}

pub fn load_firmware_from_disk(fs_id: u8) -> Result<(), WifiError> {
    if is_realtek() {
        load_realtek_firmware_from_disk(fs_id)
    } else {
        load_intel_firmware_from_disk(fs_id)
    }
}

fn load_intel_firmware_from_disk(fs_id: u8) -> Result<(), WifiError> {
    let dev = get_device().ok_or(WifiError::NotInitialized)?;

    let fs = fat32::get_fs(fs_id).ok_or(WifiError::FirmwareNotFound)?;

    let firmware_names: [&[u8]; 6] = [
        b"IWLWIFI.BIN",
        b"FIRMWARE.BIN",
        b"IWLCC77.BIN",
        b"IWLAX21.BIN",
        b"IWL8265.BIN",
        b"IWL9260.BIN",
    ];

    for name in &firmware_names {
        match fat32::find_file(&fs, *name, block_read_for_fw) {
            Ok(Some(entry)) => {
                let mut fw_buf = alloc::vec![0u8; entry.file_size as usize];
                match fat32::read_file(&fs, &entry, &mut fw_buf, block_read_for_fw) {
                    Ok(bytes_read) => {
                        if bytes_read > 0 {
                            crate::log::info!("iwlwifi: Loading firmware ({} bytes)", bytes_read);
                            let mut guard = dev.lock();
                            return guard.load_firmware(&fw_buf[..bytes_read]);
                        }
                    }
                    Err(_) => continue,
                }
            }
            _ => continue,
        }
    }

    Err(WifiError::FirmwareNotFound)
}

fn load_realtek_firmware_from_disk(fs_id: u8) -> Result<(), WifiError> {
    let dev = get_realtek_device().ok_or(WifiError::NotInitialized)?;

    let fs = fat32::get_fs(fs_id).ok_or(WifiError::FirmwareNotFound)?;

    let firmware_names: [&[u8]; 6] = [
        b"RTW88FW.BIN",
        b"RTW89FW.BIN",
        b"RTL8821.BIN",
        b"RTL8822.BIN",
        b"RTL8852.BIN",
        b"RTLWIFI.BIN",
    ];

    for name in &firmware_names {
        match fat32::find_file(&fs, *name, block_read_for_fw) {
            Ok(Some(entry)) => {
                let mut fw_buf = alloc::vec![0u8; entry.file_size as usize];
                match fat32::read_file(&fs, &entry, &mut fw_buf, block_read_for_fw) {
                    Ok(bytes_read) => {
                        if bytes_read > 0 {
                            crate::log::info!("rtlwifi: Loading firmware ({} bytes)", bytes_read);
                            let mut guard = dev.lock();
                            return guard.load_firmware(&fw_buf[..bytes_read]);
                        }
                    }
                    Err(_) => continue,
                }
            }
            _ => continue,
        }
    }

    Err(WifiError::FirmwareNotFound)
}

fn block_read_for_fw(device_id: u8, sector: u64, buffer: &mut [u8]) -> BlockResult<()> {
    let dev = block_get_device(device_id).ok_or(BlockError::InvalidDevice)?;
    match dev.device_type {
        BlockDeviceType::UsbMassStorage => {
            crate::storage::usb_msc::read_blocks(device_id, sector, 1, buffer)
        }
        _ => Err(BlockError::NotReady),
    }
}

pub(crate) fn _load_firmware_from_disk(fs_id: u8) -> Result<(), WifiError> {
    let dev = get_device().ok_or(WifiError::NotInitialized)?;

    let fs = fat32::get_fs(fs_id).ok_or(WifiError::FirmwareNotFound)?;

    let firmware_names: [&[u8]; 4] = [
        b"IWLWIFI.BIN",
        b"FIRMWARE.BIN",
        b"IWLCC77.BIN",
        b"IWLAX21.BIN",
    ];

    for name in &firmware_names {
        match fat32::find_file(&fs, *name, _block_read) {
            Ok(Some(entry)) => {
                let mut fw_buf = alloc::vec![0u8; entry.file_size as usize];
                match fat32::read_file(&fs, &entry, &mut fw_buf, _block_read) {
                    Ok(bytes_read) => {
                        if bytes_read > 0 {
                            crate::log::info!("iwlwifi: Loading firmware from disk ({} bytes)", bytes_read);
                            let mut guard = dev.lock();
                            return guard.load_firmware(&fw_buf[..bytes_read]);
                        }
                    }
                    Err(_) => continue,
                }
            }
            _ => continue,
        }
    }

    crate::log_warn!("iwlwifi: No firmware file found on disk {}", fs_id);
    Err(WifiError::FirmwareNotFound)
}

fn _block_read(device_id: u8, sector: u64, buffer: &mut [u8]) -> BlockResult<()> {
    let dev = block_get_device(device_id).ok_or(BlockError::InvalidDevice)?;
    match dev.device_type {
        BlockDeviceType::UsbMassStorage => {
            crate::storage::usb_msc::read_blocks(device_id, sector, 1, buffer)
        }
        _ => Err(BlockError::NotReady),
    }
}
