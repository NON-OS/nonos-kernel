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

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct VirtioBlkReqHeader {
    pub req_type: u32,
    pub reserved: u32,
    pub sector: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct VirtioBlkConfig {
    pub capacity: u64,
    pub size_max: u32,
    pub seg_max: u32,
    pub cylinders: u16,
    pub heads: u8,
    pub sectors: u8,
    pub blk_size: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum AccessMode {
    Io(u16),
    Mmio(u64),
}

use super::constants::{VIRTIO_BLK_S_IOERR, VIRTIO_BLK_S_OK, VIRTIO_BLK_S_UNSUPP};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlkError {
    DeviceNotFound,
    InvalidLba,
    IoError,
    Timeout,
    ReadOnly,
    Unsupported,
    QueueFull,
}

impl BlkError {
    pub fn as_str(&self) -> &'static str {
        match self {
            BlkError::DeviceNotFound => "device not found",
            BlkError::InvalidLba => "invalid LBA",
            BlkError::IoError => "I/O error",
            BlkError::Timeout => "timeout",
            BlkError::ReadOnly => "device is read-only",
            BlkError::Unsupported => "operation unsupported",
            BlkError::QueueFull => "queue full",
        }
    }

    pub fn from_status(status: u8) -> Result<(), Self> {
        match status {
            VIRTIO_BLK_S_OK => Ok(()),
            VIRTIO_BLK_S_IOERR => Err(BlkError::IoError),
            VIRTIO_BLK_S_UNSUPP => Err(BlkError::Unsupported),
            _ => Err(BlkError::IoError),
        }
    }
}
