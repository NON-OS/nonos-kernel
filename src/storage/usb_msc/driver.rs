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

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::Ordering;
use crate::storage::block::{self, BlockDeviceType, BlockError, BlockResult};
use crate::sys::serial;
use super::types::{CommandBlockWrapper, MscDevice};
use super::constants::{CSW_SIGNATURE, MAX_MSC_DEVICES};
use super::scsi::build_read_capacity_10;
use super::state::{MSC_DEVICES, MSC_DEVICE_COUNT, MSC_INIT, next_tag};

pub fn init() {
    if MSC_INIT.load(Ordering::Relaxed) {
        return;
    }

    serial::println(b"[USB-MSC] Initializing USB Mass Storage driver...");
    block::init();
    MSC_INIT.store(true, Ordering::SeqCst);
    serial::println(b"[USB-MSC] Driver initialized");
}

pub fn register_device(bulk_in_ep: u8, bulk_out_ep: u8) -> Option<u8> {
    let count = MSC_DEVICE_COUNT.load(Ordering::Relaxed) as usize;
    if count >= MAX_MSC_DEVICES {
        serial::println(b"[USB-MSC] ERROR: Maximum devices reached");
        return None;
    }

    let device = MscDevice {
        present: true,
        bulk_in_ep,
        bulk_out_ep,
        block_size: 512,
        total_blocks: 0,
    };

    // SAFETY: Single-threaded device registration
    unsafe {
        (*addr_of_mut!(MSC_DEVICES))[count] = device;
    }

    let id = count as u8;
    MSC_DEVICE_COUNT.fetch_add(1, Ordering::SeqCst);

    serial::print(b"[USB-MSC] Registered device ");
    serial::print_dec(id as u64);
    serial::println(b"");

    if query_capacity(id).is_ok() {
        // SAFETY: Read-only access after registration
        let dev = unsafe { (*addr_of!(MSC_DEVICES))[id as usize] };
        let _ = block::register_device(
            BlockDeviceType::UsbMassStorage,
            dev.block_size,
            dev.total_blocks,
            true,
            false,
        );
    }

    Some(id)
}

fn query_capacity(device_id: u8) -> BlockResult<()> {
    // SAFETY: Read-only access to static device array
    let dev = unsafe { (*addr_of!(MSC_DEVICES)).get(device_id as usize).ok_or(BlockError::InvalidDevice)? };
    if !dev.present {
        return Err(BlockError::InvalidDevice);
    }

    serial::print(b"[USB-MSC] Querying capacity for device ");
    serial::print_dec(device_id as u64);
    serial::println(b"...");

    if let Ok(capacity) = crate::drivers::usb::msc::query_capacity(device_id) {
        // SAFETY: Single-threaded capacity update after device registration
        unsafe {
            (*addr_of_mut!(MSC_DEVICES))[device_id as usize].block_size = capacity.block_size as u32;
            (*addr_of_mut!(MSC_DEVICES))[device_id as usize].total_blocks = capacity.total_blocks;
        }
        serial::print(b"[USB-MSC] Capacity: ");
        serial::print_dec(capacity.total_blocks);
        serial::print(b" blocks x ");
        serial::print_dec(capacity.block_size as u64);
        serial::println(b" bytes");
        return Ok(());
    }

    let manager = crate::drivers::usb::get_manager().ok_or(BlockError::NotReady)?;

    let cmd = build_read_capacity_10();
    let tag = next_tag();
    let cbw = CommandBlockWrapper::new(tag, 8, true, 0, &cmd);

    if manager.bulk_out_transfer(device_id, dev.bulk_out_ep, &cbw.as_bytes()).is_err() {
        serial::println(b"[USB-MSC] Failed to send READ CAPACITY command");
        return Err(BlockError::IoError);
    }

    let mut response = [0u8; 8];
    if manager.bulk_in_transfer(device_id, dev.bulk_in_ep, &mut response).is_err() {
        serial::println(b"[USB-MSC] Failed to receive capacity data");
        return Err(BlockError::IoError);
    }

    let mut csw_buf = [0u8; 13];
    if manager.bulk_in_transfer(device_id, dev.bulk_in_ep, &mut csw_buf).is_err() {
        serial::println(b"[USB-MSC] Failed to receive CSW");
        return Err(BlockError::IoError);
    }

    let last_lba = u32::from_be_bytes([response[0], response[1], response[2], response[3]]);
    let block_size = u32::from_be_bytes([response[4], response[5], response[6], response[7]]);

    // SAFETY: Single-threaded capacity update
    unsafe {
        (*addr_of_mut!(MSC_DEVICES))[device_id as usize].block_size = block_size;
        (*addr_of_mut!(MSC_DEVICES))[device_id as usize].total_blocks = (last_lba as u64) + 1;
    }

    serial::print(b"[USB-MSC] Capacity: ");
    serial::print_dec((last_lba as u64) + 1);
    serial::print(b" blocks x ");
    serial::print_dec(block_size as u64);
    serial::println(b" bytes");

    Ok(())
}
