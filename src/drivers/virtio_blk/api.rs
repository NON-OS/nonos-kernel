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

use super::constants::{VIRTIO_BLK_DEVICE_ID_TRANSITIONAL, VIRTIO_BLK_VENDOR_ID};
use super::device::VirtioBlkDevice;
use super::types::BlkError;
use spin::Mutex;

static DEVICE: Mutex<Option<VirtioBlkDevice>> = Mutex::new(None);

pub fn init() -> Result<(), &'static str> {
    let manager = crate::drivers::pci::get_pci_manager().ok_or("pci: manager not initialized")?;
    let mgr = manager.lock();
    for dev in mgr.devices() {
        if dev.device_id_info.vendor_id == VIRTIO_BLK_VENDOR_ID
            && dev.device_id_info.device_id == VIRTIO_BLK_DEVICE_ID_TRANSITIONAL
        {
            let bar0 = match &dev.bars[0] {
                crate::drivers::pci::PciBar::Io { port, .. } => (*port as u32) | 1,
                bar => bar.address().ok_or("virtio-blk: BAR0 not memory")?.as_u64() as u32,
            };
            drop(mgr);
            let blk_dev = VirtioBlkDevice::from_bar0(bar0)?;
            *DEVICE.lock() = Some(blk_dev);
            return Ok(());
        }
    }
    Err("virtio-blk: no device found")
}

pub fn read(start_sector: u64, buf: &mut [u8]) -> Result<(), BlkError> {
    DEVICE.lock().as_mut().ok_or(BlkError::DeviceNotFound)?.read_sectors(start_sector, buf)
}

pub fn write(start_sector: u64, buf: &[u8]) -> Result<(), BlkError> {
    DEVICE.lock().as_mut().ok_or(BlkError::DeviceNotFound)?.write_sectors(start_sector, buf)
}

pub fn flush() -> Result<(), BlkError> {
    DEVICE.lock().as_mut().ok_or(BlkError::DeviceNotFound)?.flush()
}

pub fn capacity() -> Result<u64, BlkError> {
    Ok(DEVICE.lock().as_ref().ok_or(BlkError::DeviceNotFound)?.sector_count())
}

pub fn is_initialized() -> bool {
    DEVICE.lock().as_ref().map(|d| d.is_initialized()).unwrap_or(false)
}

pub fn is_read_only() -> Result<bool, BlkError> {
    Ok(DEVICE.lock().as_ref().ok_or(BlkError::DeviceNotFound)?.is_read_only())
}

pub fn get_device_id(id_buf: &mut [u8; 20]) -> Result<(), BlkError> {
    DEVICE.lock().as_mut().ok_or(BlkError::DeviceNotFound)?.get_device_id(id_buf)
}

pub fn discard(start_sector: u64, count: u64) -> Result<(), BlkError> {
    DEVICE.lock().as_mut().ok_or(BlkError::DeviceNotFound)?.discard_sectors(start_sector, count)
}

pub fn write_zeroes(start_sector: u64, count: u64) -> Result<(), BlkError> {
    DEVICE.lock().as_mut().ok_or(BlkError::DeviceNotFound)?.write_zeroes(start_sector, count)
}
