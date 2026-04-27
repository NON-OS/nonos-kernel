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

use crate::fs::devfs::registry::register_device_with_ops;
use crate::fs::devfs::types::{DeviceOps, DeviceType};
use alloc::string::String;
use alloc::sync::Arc;

pub struct StorageDevice {
    name: String,
    major: u32,
    minor: u32,
    size: u64,
}

impl StorageDevice {
    pub fn dev_t(&self) -> u64 {
        ((self.major as u64) << 8) | (self.minor as u64)
    }
}

impl DeviceOps for StorageDevice {
    fn open(&self, _flags: u32) -> Result<(), i32> {
        crate::drivers::block::open(&self.name)
    }

    fn close(&self) -> Result<(), i32> {
        crate::drivers::block::close(&self.name)
    }

    fn read(&self, buf: &mut [u8], offset: u64) -> Result<usize, i32> {
        crate::drivers::block::read(&self.name, buf, offset)
    }

    fn write(&self, buf: &[u8], offset: u64) -> Result<usize, i32> {
        crate::drivers::block::write(&self.name, buf, offset)
    }

    fn ioctl(&self, cmd: u32, arg: u64) -> Result<i64, i32> {
        match cmd {
            0x1260 => Ok((self.size / 512) as i64),
            0x1268 => Ok(self.size as i64),
            0x1271 => Ok(512),
            0x1272 => Ok(4096),
            0x1277 => {
                crate::drivers::block::flush(&self.name)?;
                Ok(0)
            }
            0x80041272 => Ok(self.dev_t() as i64),
            _ => crate::drivers::block::ioctl(&self.name, cmd, arg),
        }
    }

    fn poll(&self) -> u32 {
        0x05
    }
}

pub fn register_storage_device(name: &str, major: u32, minor: u32, size: u64) -> u64 {
    let dev = StorageDevice { name: String::from(name), major, minor, size };
    register_device_with_ops(name, DeviceType::BlockDevice, major, minor, 0o660, Arc::new(dev))
        .unwrap_or(0)
}
