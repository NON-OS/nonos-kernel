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

use crate::storage::block::{
    get_device as block_get_device, BlockDeviceType, BlockError, BlockResult,
};

pub(super) fn is_disk_path(path: &str) -> bool {
    path.starts_with("/disk/")
}

pub(super) fn parse_disk_path(path: &str) -> Option<(u8, &str)> {
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

pub(super) fn block_read(device_id: u8, sector: u64, buffer: &mut [u8]) -> BlockResult<()> {
    let dev = block_get_device(device_id).ok_or(BlockError::InvalidDevice)?;
    match dev.device_type {
        BlockDeviceType::UsbMassStorage => {
            crate::storage::usb_msc::read_blocks(device_id, sector, 1, buffer)
        }
        BlockDeviceType::SataAhci | BlockDeviceType::Nvme => Err(BlockError::NotReady),
        BlockDeviceType::Unknown => Err(BlockError::InvalidDevice),
    }
}

pub(super) fn block_write(device_id: u8, sector: u64, buffer: &[u8]) -> BlockResult<()> {
    let dev = block_get_device(device_id).ok_or(BlockError::InvalidDevice)?;
    if dev.read_only {
        return Err(BlockError::ReadOnly);
    }
    match dev.device_type {
        BlockDeviceType::UsbMassStorage => {
            crate::storage::usb_msc::write_blocks(device_id, sector, 1, buffer)
        }
        BlockDeviceType::SataAhci | BlockDeviceType::Nvme => Err(BlockError::NotReady),
        BlockDeviceType::Unknown => Err(BlockError::InvalidDevice),
    }
}
