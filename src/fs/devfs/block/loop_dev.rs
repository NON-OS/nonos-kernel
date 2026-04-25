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

use crate::fs::devfs::major_minor::LOOP_MAJOR;
use crate::fs::devfs::registry::register_device_with_ops;
use crate::fs::devfs::types::{DeviceOps, DeviceType};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use spin::Mutex;

static LOOP_BACKING: Mutex<BTreeMap<u32, LoopBacking>> = Mutex::new(BTreeMap::new());

struct LoopBacking {
    fd: i32,
    offset: u64,
    size: u64,
}

pub struct LoopDevice {
    minor: u32,
}

impl DeviceOps for LoopDevice {
    fn open(&self, _flags: u32) -> Result<(), i32> {
        Ok(())
    }
    fn close(&self) -> Result<(), i32> {
        Ok(())
    }
    fn read(&self, buf: &mut [u8], offset: u64) -> Result<usize, i32> {
        let backing = LOOP_BACKING.lock();
        let b = backing.get(&self.minor).ok_or(-6)?;
        crate::fs::pread(b.fd, buf, b.offset + offset)
    }
    fn write(&self, buf: &[u8], offset: u64) -> Result<usize, i32> {
        let backing = LOOP_BACKING.lock();
        let b = backing.get(&self.minor).ok_or(-6)?;
        crate::fs::pwrite(b.fd, buf, b.offset + offset)
    }
    fn ioctl(&self, cmd: u32, arg: u64) -> Result<i64, i32> {
        match cmd {
            0x4C00 => setup_loop(self.minor, arg as i32, 0, 0).map(|_| 0),
            0x4C01 => clear_loop(self.minor).map(|_| 0),
            0x4C02 => get_loop_status(self.minor).map(|s| s as i64),
            _ => Err(-25),
        }
    }
    fn poll(&self) -> u32 {
        0x05
    }
}

pub fn register_loop_device(minor: u32) {
    let name = alloc::format!("loop{}", minor);
    let _ = register_device_with_ops(
        &name,
        DeviceType::BlockDevice,
        LOOP_MAJOR,
        minor,
        0o660,
        Arc::new(LoopDevice { minor }),
    );
}

pub fn setup_loop(minor: u32, fd: i32, offset: u64, size: u64) -> Result<(), i32> {
    let sz = if size == 0 { crate::fs::get_file_size(fd)? } else { size };
    LOOP_BACKING.lock().insert(minor, LoopBacking { fd, offset, size: sz });
    Ok(())
}

pub fn clear_loop(minor: u32) -> Result<(), i32> {
    LOOP_BACKING.lock().remove(&minor).ok_or(-6)?;
    Ok(())
}

fn get_loop_status(minor: u32) -> Result<u64, i32> {
    LOOP_BACKING.lock().get(&minor).map(|b| b.size).ok_or(-6)
}
