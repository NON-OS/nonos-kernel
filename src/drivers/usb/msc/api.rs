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

use alloc::sync::Arc;
use alloc::vec::Vec;
use super::capacity::StorageCapacity;
use super::inquiry::InquiryResponse;
use super::registry::{get_msc_device, get_msc_devices};
use super::commands::{get_capacity, read_blocks_auto, write_blocks_auto, sync_cache, is_write_protected};
use super::driver::MscClassDriver;

pub fn query_capacity(slot_id: u8) -> Result<StorageCapacity, &'static str> {
    let device = get_msc_device(slot_id).ok_or("Device not found")?;
    let state = device.lock();

    if let Some(cap) = state.capacity {
        return Ok(cap);
    }

    get_capacity(&state)
}

pub fn query_all_capacities() -> Vec<(u8, Result<StorageCapacity, &'static str>)> {
    get_msc_devices()
        .iter()
        .map(|dev| {
            let state = dev.lock();
            let cap = state.capacity.ok_or("Capacity not available")
                .or_else(|_| get_capacity(&state));
            (state.slot_id, cap)
        })
        .collect()
}

pub fn read_sector(slot_id: u8, lba: u64, buffer: &mut [u8]) -> Result<usize, &'static str> {
    let device = get_msc_device(slot_id).ok_or("Device not found")?;
    let state = device.lock();

    let block_size = state.capacity.map(|c| c.block_size).unwrap_or(512);
    if buffer.len() < block_size as usize {
        return Err("Buffer too small");
    }

    read_blocks_auto(&state, lba, 1, buffer)
}

pub fn write_sector(slot_id: u8, lba: u64, data: &[u8]) -> Result<usize, &'static str> {
    let device = get_msc_device(slot_id).ok_or("Device not found")?;
    let state = device.lock();

    if is_write_protected(&state).unwrap_or(false) {
        return Err("Device is write-protected");
    }

    write_blocks_auto(&state, lba, 1, data)
}

pub fn flush_device(slot_id: u8) -> Result<(), &'static str> {
    let device = get_msc_device(slot_id).ok_or("Device not found")?;
    let state = device.lock();
    sync_cache(&state)
}

pub fn get_device_info(slot_id: u8) -> Option<(InquiryResponse, StorageCapacity)> {
    let device = get_msc_device(slot_id)?;
    let state = device.lock();
    Some((state.inquiry.clone()?, state.capacity?))
}

pub fn init_msc_driver() {
    crate::drivers::usb::register_class_driver(Arc::new(MscClassDriver));
    crate::log_info!("[USB MSC] Driver initialized");
}
