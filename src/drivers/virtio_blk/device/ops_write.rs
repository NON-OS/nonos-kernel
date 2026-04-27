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

use super::core::VirtioBlkDevice;
use crate::drivers::virtio_blk::constants::{SECTOR_SIZE, VIRTIO_BLK_T_FLUSH, VIRTIO_BLK_T_OUT};
use crate::drivers::virtio_blk::types::BlkError;

impl VirtioBlkDevice {
    pub(crate) fn write_sectors(&mut self, start_sector: u64, buf: &[u8]) -> Result<(), BlkError> {
        if !self.initialized {
            return Err(BlkError::DeviceNotFound);
        }
        if self.read_only {
            return Err(BlkError::ReadOnly);
        }
        let sector_count = buf.len() / SECTOR_SIZE;
        if start_sector + sector_count as u64 > self.capacity {
            return Err(BlkError::InvalidLba);
        }
        self.queue
            .submit_request(VIRTIO_BLK_T_OUT, start_sector, buf, true)
            .map_err(|_| BlkError::QueueFull)?;
        self.wait_completion()?;
        let mut status_buf = [0u8; 1];
        self.queue.complete_request(&mut status_buf).map_err(|_| BlkError::IoError)?;
        Ok(())
    }

    pub(crate) fn flush(&mut self) -> Result<(), BlkError> {
        if !self.initialized {
            return Err(BlkError::DeviceNotFound);
        }
        self.queue
            .submit_request(VIRTIO_BLK_T_FLUSH, 0, &[], false)
            .map_err(|_| BlkError::QueueFull)?;
        self.wait_completion()?;
        let mut status_buf = [0u8; 1];
        self.queue.complete_request(&mut status_buf).map_err(|_| BlkError::IoError)?;
        Ok(())
    }
}
