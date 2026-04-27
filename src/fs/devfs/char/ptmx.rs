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

use crate::fs::devfs::major_minor::TTYAUX_MAJOR;
use crate::fs::devfs::registry::register_device_with_ops;
use crate::fs::devfs::types::{DeviceOps, DeviceType};
use alloc::sync::Arc;

pub struct PtmxDevice;

impl DeviceOps for PtmxDevice {
    fn open(&self, _flags: u32) -> Result<(), i32> {
        Ok(())
    }

    fn close(&self) -> Result<(), i32> {
        Ok(())
    }

    fn read(&self, buf: &mut [u8], _offset: u64) -> Result<usize, i32> {
        let pty_num = get_current_pty()?;
        crate::tty::pty::master_read(pty_num, buf)
    }

    fn write(&self, buf: &[u8], _offset: u64) -> Result<usize, i32> {
        let pty_num = get_current_pty()?;
        crate::tty::pty::master_write(pty_num, buf)
    }

    fn ioctl(&self, cmd: u32, arg: u64) -> Result<i64, i32> {
        match cmd {
            0x5430 => {
                let pty_num = crate::fs::devfs::pts::allocate_pty()?;
                Ok(pty_num as i64)
            }
            0x4004_5431 => {
                let pty_num = get_current_pty()?;
                crate::tty::pty::unlock(pty_num)?;
                Ok(0)
            }
            0x8004_5430 => {
                let pty_num = get_current_pty()?;
                Ok(pty_num as i64)
            }
            _ => {
                let pty_num = get_current_pty()?;
                crate::tty::pty::master_ioctl(pty_num, cmd, arg)
            }
        }
    }

    fn poll(&self) -> u32 {
        get_current_pty().map(|n| crate::tty::pty::master_poll(n)).unwrap_or(0)
    }
}

fn get_current_pty() -> Result<u32, i32> {
    crate::process::get_current_pty().ok_or(-9)
}

pub fn register_ptmx() {
    let _ = register_device_with_ops(
        "ptmx",
        DeviceType::CharDevice,
        TTYAUX_MAJOR,
        2,
        0o666,
        Arc::new(PtmxDevice),
    );
}
