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

use crate::storage::block::{BlockDeviceType, BlockError, BlockResult, get_device as block_get_device};

pub(crate) fn block_read(device_id: u8, sector: u64, buffer: &mut [u8]) -> BlockResult<()> {
    let dev = block_get_device(device_id).ok_or(BlockError::InvalidDevice)?;
    match dev.device_type {
        BlockDeviceType::UsbMassStorage => {
            crate::storage::usb_msc::read_blocks(device_id, sector, 1, buffer)
        }
        _ => Err(BlockError::NotReady),
    }
}

pub(crate) fn block_write(device_id: u8, sector: u64, buffer: &[u8]) -> BlockResult<()> {
    let dev = block_get_device(device_id).ok_or(BlockError::InvalidDevice)?;
    if dev.read_only {
        return Err(BlockError::ReadOnly);
    }
    match dev.device_type {
        BlockDeviceType::UsbMassStorage => {
            crate::storage::usb_msc::write_blocks(device_id, sector, 1, buffer)
        }
        _ => Err(BlockError::NotReady),
    }
}
