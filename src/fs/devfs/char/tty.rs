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

use crate::fs::devfs::major_minor::{TTYAUX_MAJOR, TTY_MAJOR};
use crate::fs::devfs::registry::register_device_with_ops;
use crate::fs::devfs::types::{DeviceOps, DeviceType};
use alloc::sync::Arc;

pub struct TtyDevice {
    pub minor: u32,
}
pub struct ConsoleDevice;

impl DeviceOps for TtyDevice {
    fn open(&self, _flags: u32) -> Result<(), i32> {
        Ok(())
    }
    fn close(&self) -> Result<(), i32> {
        Ok(())
    }
    fn read(&self, buf: &mut [u8], _offset: u64) -> Result<usize, i32> {
        crate::tty::read(self.minor, buf)
    }
    fn write(&self, buf: &[u8], _offset: u64) -> Result<usize, i32> {
        crate::tty::write(self.minor, buf)
    }
    fn ioctl(&self, cmd: u32, arg: u64) -> Result<i64, i32> {
        crate::tty::ioctl(self.minor, cmd, arg)
    }
    fn poll(&self) -> u32 {
        crate::tty::poll(self.minor)
    }
}

impl DeviceOps for ConsoleDevice {
    fn open(&self, _flags: u32) -> Result<(), i32> {
        Ok(())
    }
    fn close(&self) -> Result<(), i32> {
        Ok(())
    }
    fn read(&self, buf: &mut [u8], _offset: u64) -> Result<usize, i32> {
        crate::tty::console_read(buf)
    }
    fn write(&self, buf: &[u8], _offset: u64) -> Result<usize, i32> {
        crate::tty::console_write(buf)
    }
    fn ioctl(&self, cmd: u32, arg: u64) -> Result<i64, i32> {
        crate::tty::console_ioctl(cmd, arg)
    }
    fn poll(&self) -> u32 {
        crate::tty::console_poll()
    }
}

pub fn register_tty_devices() {
    let _ = register_device_with_ops(
        "tty",
        DeviceType::CharDevice,
        TTYAUX_MAJOR,
        0,
        0o666,
        Arc::new(TtyDevice { minor: 0 }),
    );
    let _ = register_device_with_ops(
        "console",
        DeviceType::CharDevice,
        TTYAUX_MAJOR,
        1,
        0o620,
        Arc::new(ConsoleDevice),
    );
    for i in 0..8 {
        let name = alloc::format!("tty{}", i);
        let _ = register_device_with_ops(
            &name,
            DeviceType::CharDevice,
            TTY_MAJOR,
            i,
            0o620,
            Arc::new(TtyDevice { minor: i }),
        );
    }
}
