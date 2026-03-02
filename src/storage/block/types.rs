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

pub const BLOCK_SIZE: usize = 512;
pub const MAX_BLOCK_DEVICES: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BlockDeviceType {
    Unknown,
    UsbMassStorage,
    SataAhci,
    Nvme,
}

#[derive(Clone, Copy, Debug)]
pub struct BlockDevice {
    pub id: u8,
    pub device_type: BlockDeviceType,
    pub block_size: u32,
    pub total_blocks: u64,
    pub removable: bool,
    pub read_only: bool,
    pub present: bool,
}

impl BlockDevice {
    pub const fn empty() -> Self {
        Self {
            id: 0xFF,
            device_type: BlockDeviceType::Unknown,
            block_size: 512,
            total_blocks: 0,
            removable: false,
            read_only: false,
            present: false,
        }
    }

    pub fn capacity_bytes(&self) -> u64 {
        self.total_blocks * self.block_size as u64
    }

    pub fn capacity_mb(&self) -> u64 {
        self.capacity_bytes() / (1024 * 1024)
    }

    pub fn capacity_gb(&self) -> u64 {
        self.capacity_bytes() / (1024 * 1024 * 1024)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BlockError {
    InvalidDevice,
    InvalidBlock,
    ReadOnly,
    DeviceBusy,
    IoError,
    Timeout,
    NotReady,
}

pub type BlockResult<T> = Result<T, BlockError>;

pub trait BlockOps {
    fn read_blocks(&self, start_block: u64, count: u32, buffer: &mut [u8]) -> BlockResult<()>;
    fn write_blocks(&self, start_block: u64, count: u32, buffer: &[u8]) -> BlockResult<()>;
    fn sync(&self) -> BlockResult<()>;
}
