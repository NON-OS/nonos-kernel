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

use crate::fs::devfs::major_minor::{MEM_MAJOR, NULL_MINOR};
use crate::fs::devfs::registry::register_device_with_ops;
use crate::fs::devfs::types::{DeviceOps, DeviceType};
use alloc::sync::Arc;

pub struct NullDevice;

impl DeviceOps for NullDevice {
    fn open(&self, _flags: u32) -> Result<(), i32> {
        Ok(())
    }

    fn close(&self) -> Result<(), i32> {
        Ok(())
    }

    fn read(&self, _buf: &mut [u8], _offset: u64) -> Result<usize, i32> {
        Ok(0)
    }

    fn write(&self, buf: &[u8], _offset: u64) -> Result<usize, i32> {
        Ok(buf.len())
    }

    fn ioctl(&self, _cmd: u32, _arg: u64) -> Result<i64, i32> {
        Err(-25)
    }

    fn poll(&self) -> u32 {
        0x05
    }
}

pub fn register_null() {
    let _ = register_device_with_ops(
        "null",
        DeviceType::CharDevice,
        MEM_MAJOR,
        NULL_MINOR,
        0o666,
        Arc::new(NullDevice),
    );
}
