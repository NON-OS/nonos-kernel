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

extern crate alloc;

use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::Ordering;
use spin::RwLock;
use x86_64::VirtAddr;

use crate::storage::{
    DeviceCapabilities, DeviceInfo, DeviceStatistics, IoStatus, StorageType, StorageManager,
};

pub struct RamDisk {
    pub(super) data: RwLock<Vec<u8>>,
    pub(super) block_size: u32,
    pub(super) info: DeviceInfo,
    pub(super) stats: DeviceStatistics,
}

impl RamDisk {
    pub fn new(capacity_bytes: u64, block_size: u32, vendor: &str, model: &str) -> Arc<Self> {
        let size = capacity_bytes as usize;
        let mut buf = Vec::with_capacity(size);
        // SAFETY: Capacity is pre-allocated, filling with zeros
        unsafe { buf.set_len(size) }
        let info = DeviceInfo {
            device_type: StorageType::RamDisk,
            vendor: String::from(vendor),
            model: String::from(model),
            serial: String::from("RAMDISK-0001"),
            firmware: String::from("rd-1.0"),
            firmware_version: String::from("rd-1.0"),
            capacity: capacity_bytes / block_size as u64,
            capacity_bytes,
            block_size,
            max_transfer_size: 1024 * 1024,
            max_queue_depth: 64,
            features: DeviceCapabilities::READ | DeviceCapabilities::WRITE | DeviceCapabilities::FLUSH,
        };
        Arc::new(Self {
            data: RwLock::new(buf),
            block_size,
            info,
            stats: DeviceStatistics::default(),
        })
    }

    #[inline]
    pub(super) fn bs(&self) -> usize {
        self.block_size as usize
    }

    pub(super) fn read_into(&self, start_block: u64, block_count: u32, out: &mut [u8]) -> Result<(), IoStatus> {
        let start = (start_block as usize) * self.bs();
        let len = (block_count as usize) * self.bs();
        if out.len() < len {
            return Err(IoStatus::InvalidRequest);
        }
        let data = self.data.read();
        if start.checked_add(len).filter(|end| *end <= data.len()).is_none() {
            return Err(IoStatus::InvalidRequest);
        }
        out[..len].copy_from_slice(&data[start..start + len]);
        self.stats.reads_completed.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_read.fetch_add(len as u64, Ordering::Relaxed);
        Ok(())
    }

    pub(super) fn write_from(&self, start_block: u64, block_count: u32, inp: &[u8]) -> Result<(), IoStatus> {
        let start = (start_block as usize) * self.bs();
        let len = (block_count as usize) * self.bs();
        if inp.len() < len {
            return Err(IoStatus::InvalidRequest);
        }
        let mut data = self.data.write();
        if start.checked_add(len).filter(|end| *end <= data.len()).is_none() {
            return Err(IoStatus::InvalidRequest);
        }
        data[start..start + len].copy_from_slice(&inp[..len]);
        self.stats.writes_completed.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_written.fetch_add(len as u64, Ordering::Relaxed);
        Ok(())
    }

    #[inline]
    pub(super) unsafe fn buf_mut_from_virt<'a>(va: VirtAddr, len: usize) -> &'a mut [u8] {
        // SAFETY: Caller ensures virtual address is valid and mapped
        unsafe { core::slice::from_raw_parts_mut(va.as_mut_ptr(), len) }
    }

    #[inline]
    pub(super) unsafe fn buf_from_virt<'a>(va: VirtAddr, len: usize) -> &'a [u8] {
        // SAFETY: Caller ensures virtual address is valid and mapped
        unsafe { core::slice::from_raw_parts(va.as_ptr(), len) }
    }

    pub fn ensure_default_registered(manager: &StorageManager) {
        if manager.get_device(0).is_none() {
            let rd = RamDisk::new(64 * 1024 * 1024, 4096, "NONOS", "RAMDISK");
            let _ = manager.register_device(rd);
        }
    }
}
