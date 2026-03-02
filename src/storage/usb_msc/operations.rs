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

use core::ptr::addr_of;
use crate::storage::block::{BlockError, BlockResult};
use super::types::CommandBlockWrapper;
use super::constants::CSW_SIGNATURE;
use super::scsi::{build_test_unit_ready, build_read_10, build_write_10};
use super::state::{MSC_DEVICES, next_tag};

pub fn read_blocks(device_id: u8, start_lba: u64, count: u32, buffer: &mut [u8]) -> BlockResult<()> {
    // SAFETY: Read-only access to static device array
    let dev = unsafe { (*addr_of!(MSC_DEVICES)).get(device_id as usize).ok_or(BlockError::InvalidDevice)? };
    if !dev.present {
        return Err(BlockError::InvalidDevice);
    }

    if start_lba + count as u64 > dev.total_blocks && dev.total_blocks > 0 {
        return Err(BlockError::InvalidBlock);
    }

    let expected_size = count as usize * dev.block_size as usize;
    if buffer.len() < expected_size {
        return Err(BlockError::IoError);
    }

    if start_lba > 0xFFFFFFFF {
        return Err(BlockError::InvalidBlock);
    }

    if let Some(msc_dev) = crate::drivers::usb::msc::get_msc_device(device_id) {
        let state = msc_dev.lock();
        let count16 = count.min(0xFFFF) as u16;
        if crate::drivers::usb::msc::read_blocks(&state, start_lba, count16, buffer).is_ok() {
            return Ok(());
        }
    }

    let manager = crate::drivers::usb::get_manager().ok_or(BlockError::NotReady)?;

    let lba32 = start_lba as u32;
    let count16 = count.min(0xFFFF) as u16;
    let cmd = build_read_10(lba32, count16);
    let tag = next_tag();
    let cbw = CommandBlockWrapper::new(tag, expected_size as u32, true, 0, &cmd);

    if manager.bulk_out_transfer(device_id, dev.bulk_out_ep, &cbw.as_bytes()).is_err() {
        return Err(BlockError::IoError);
    }

    if manager.bulk_in_transfer(device_id, dev.bulk_in_ep, buffer).is_err() {
        return Err(BlockError::IoError);
    }

    let mut csw_buf = [0u8; 13];
    if manager.bulk_in_transfer(device_id, dev.bulk_in_ep, &mut csw_buf).is_err() {
        return Err(BlockError::IoError);
    }

    let csw_sig = u32::from_le_bytes([csw_buf[0], csw_buf[1], csw_buf[2], csw_buf[3]]);
    let csw_status = csw_buf[12];

    if csw_sig != CSW_SIGNATURE || csw_status != 0 {
        return Err(BlockError::IoError);
    }

    Ok(())
}

pub fn write_blocks(device_id: u8, start_lba: u64, count: u32, buffer: &[u8]) -> BlockResult<()> {
    // SAFETY: Read-only access to static device array
    let dev = unsafe { (*addr_of!(MSC_DEVICES)).get(device_id as usize).ok_or(BlockError::InvalidDevice)? };
    if !dev.present {
        return Err(BlockError::InvalidDevice);
    }

    if start_lba + count as u64 > dev.total_blocks && dev.total_blocks > 0 {
        return Err(BlockError::InvalidBlock);
    }

    let expected_size = count as usize * dev.block_size as usize;
    if buffer.len() < expected_size {
        return Err(BlockError::IoError);
    }

    if start_lba > 0xFFFFFFFF {
        return Err(BlockError::InvalidBlock);
    }

    if let Some(msc_dev) = crate::drivers::usb::msc::get_msc_device(device_id) {
        let state = msc_dev.lock();
        let count16 = count.min(0xFFFF) as u16;
        if crate::drivers::usb::msc::write_blocks(&state, start_lba, count16, buffer).is_ok() {
            return Ok(());
        }
    }

    let manager = crate::drivers::usb::get_manager().ok_or(BlockError::NotReady)?;

    let lba32 = start_lba as u32;
    let count16 = count.min(0xFFFF) as u16;
    let cmd = build_write_10(lba32, count16);
    let tag = next_tag();
    let cbw = CommandBlockWrapper::new(tag, expected_size as u32, false, 0, &cmd);

    if manager.bulk_out_transfer(device_id, dev.bulk_out_ep, &cbw.as_bytes()).is_err() {
        return Err(BlockError::IoError);
    }

    if manager.bulk_out_transfer(device_id, dev.bulk_out_ep, buffer).is_err() {
        return Err(BlockError::IoError);
    }

    let mut csw_buf = [0u8; 13];
    if manager.bulk_in_transfer(device_id, dev.bulk_in_ep, &mut csw_buf).is_err() {
        return Err(BlockError::IoError);
    }

    let csw_sig = u32::from_le_bytes([csw_buf[0], csw_buf[1], csw_buf[2], csw_buf[3]]);
    let csw_status = csw_buf[12];

    if csw_sig != CSW_SIGNATURE || csw_status != 0 {
        return Err(BlockError::IoError);
    }

    Ok(())
}

pub fn test_unit_ready(device_id: u8) -> BlockResult<bool> {
    // SAFETY: Read-only access to static device array
    let dev = unsafe { (*addr_of!(MSC_DEVICES)).get(device_id as usize).ok_or(BlockError::InvalidDevice)? };
    if !dev.present {
        return Err(BlockError::InvalidDevice);
    }

    if let Some(msc_dev) = crate::drivers::usb::msc::get_msc_device(device_id) {
        let state = msc_dev.lock();
        return crate::drivers::usb::msc::test_unit_ready(&state)
            .map_err(|_| BlockError::IoError);
    }

    let manager = crate::drivers::usb::get_manager().ok_or(BlockError::NotReady)?;

    let cmd = build_test_unit_ready();
    let tag = next_tag();
    let cbw = CommandBlockWrapper::new(tag, 0, false, 0, &cmd);

    if manager.bulk_out_transfer(device_id, dev.bulk_out_ep, &cbw.as_bytes()).is_err() {
        return Err(BlockError::IoError);
    }

    let mut csw_buf = [0u8; 13];
    if manager.bulk_in_transfer(device_id, dev.bulk_in_ep, &mut csw_buf).is_err() {
        return Err(BlockError::IoError);
    }

    let csw_sig = u32::from_le_bytes([csw_buf[0], csw_buf[1], csw_buf[2], csw_buf[3]]);
    let csw_status = csw_buf[12];

    if csw_sig != CSW_SIGNATURE {
        return Err(BlockError::IoError);
    }

    Ok(csw_status == 0)
}
