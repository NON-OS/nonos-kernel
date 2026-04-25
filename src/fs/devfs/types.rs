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

use alloc::string::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    CharDevice,
    BlockDevice,
}

#[derive(Debug, Clone)]
pub struct DeviceNode {
    pub name: String,
    pub dev_type: DeviceType,
    pub major: u32,
    pub minor: u32,
    pub mode: u32,
    pub inode: u64,
}

pub trait DeviceOps: Send + Sync {
    fn open(&self, flags: u32) -> Result<(), i32>;
    fn close(&self) -> Result<(), i32>;
    fn read(&self, buf: &mut [u8], offset: u64) -> Result<usize, i32>;
    fn write(&self, buf: &[u8], offset: u64) -> Result<usize, i32>;
    fn ioctl(&self, cmd: u32, arg: u64) -> Result<i64, i32>;
    fn poll(&self) -> u32;
}

impl DeviceNode {
    pub fn char_device(name: &str, major: u32, minor: u32, mode: u32, inode: u64) -> Self {
        Self {
            name: String::from(name),
            dev_type: DeviceType::CharDevice,
            major,
            minor,
            mode,
            inode,
        }
    }

    pub fn block_device(name: &str, major: u32, minor: u32, mode: u32, inode: u64) -> Self {
        Self {
            name: String::from(name),
            dev_type: DeviceType::BlockDevice,
            major,
            minor,
            mode,
            inode,
        }
    }

    pub fn dev(&self) -> u64 {
        super::major_minor::make_dev(self.major, self.minor)
    }

    pub fn is_char(&self) -> bool {
        self.dev_type == DeviceType::CharDevice
    }

    pub fn is_block(&self) -> bool {
        self.dev_type == DeviceType::BlockDevice
    }
}

pub struct NullOps;
impl DeviceOps for NullOps {
    fn open(&self, _: u32) -> Result<(), i32> {
        Ok(())
    }
    fn close(&self) -> Result<(), i32> {
        Ok(())
    }
    fn read(&self, _: &mut [u8], _: u64) -> Result<usize, i32> {
        Ok(0)
    }
    fn write(&self, buf: &[u8], _: u64) -> Result<usize, i32> {
        Ok(buf.len())
    }
    fn ioctl(&self, _: u32, _: u64) -> Result<i64, i32> {
        Err(-25)
    }
    fn poll(&self) -> u32 {
        0x05
    }
}
