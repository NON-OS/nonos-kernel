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

pub trait BlockDevice: Send + Sync {
    fn read(&self, buf: &mut [u8], offset: u64) -> Result<usize, i32>;
    fn write(&self, buf: &[u8], offset: u64) -> Result<usize, i32>;
    fn flush(&self) -> Result<(), i32>;
    fn ioctl(&self, cmd: u32, arg: u64) -> Result<i64, i32>;
    fn block_size(&self) -> u32;
    fn total_blocks(&self) -> u64;
}

#[derive(Clone)]
pub struct BlockDeviceInfo {
    pub name: String,
    pub block_size: u32,
    pub total_blocks: u64,
    pub read_only: bool,
    pub size_bytes: u64,
}

impl BlockDeviceInfo {
    pub fn new(name: &str, block_size: u32, total_blocks: u64, read_only: bool) -> Self {
        let size_bytes = block_size as u64 * total_blocks;
        Self { name: String::from(name), block_size, total_blocks, read_only, size_bytes }
    }

    pub fn capacity(&self) -> u64 {
        self.size_bytes
    }
}
