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
use crate::drivers::virtio_blk::constants::{
    MAX_SECTORS_PER_REQUEST, VIRTIO_BLK_T_DISCARD, VIRTIO_BLK_T_GET_ID, VIRTIO_BLK_T_WRITE_ZEROES,
};
use crate::drivers::virtio_blk::types::BlkError;

impl VirtioBlkDevice {
    pub(crate) fn get_device_id(&mut self, id_buf: &mut [u8; 20]) -> Result<(), BlkError> {
        if !self.initialized {
            return Err(BlkError::DeviceNotFound);
        }
        self.queue
            .submit_request(VIRTIO_BLK_T_GET_ID, 0, &[], false)
            .map_err(|_| BlkError::QueueFull)?;
        self.wait_completion()?;
        self.queue.complete_request(id_buf).map_err(|_| BlkError::IoError)?;
        Ok(())
    }

    pub(crate) fn discard_sectors(
        &mut self,
        start_sector: u64,
        count: u64,
    ) -> Result<(), BlkError> {
        if !self.initialized {
            return Err(BlkError::DeviceNotFound);
        }
        if !self.supports_discard {
            return Err(BlkError::Unsupported);
        }
        if start_sector + count > self.capacity {
            return Err(BlkError::InvalidLba);
        }
        if count > self.max_sectors_per_request() as u64 {
            return Err(BlkError::InvalidLba);
        }
        let discard_buf: [u8; 16] =
            unsafe { core::mem::transmute((start_sector, count as u32, 0u32)) };
        self.queue
            .submit_request(VIRTIO_BLK_T_DISCARD, 0, &discard_buf, true)
            .map_err(|_| BlkError::QueueFull)?;
        self.wait_completion()?;
        let mut status_buf = [0u8; 1];
        self.queue.complete_request(&mut status_buf).map_err(|_| BlkError::IoError)?;
        Ok(())
    }

    pub(crate) fn write_zeroes(&mut self, start_sector: u64, count: u64) -> Result<(), BlkError> {
        if !self.initialized {
            return Err(BlkError::DeviceNotFound);
        }
        if start_sector + count > self.capacity {
            return Err(BlkError::InvalidLba);
        }
        let zeroes_buf: [u8; 16] =
            unsafe { core::mem::transmute((start_sector, count as u32, 0u32)) };
        self.queue
            .submit_request(VIRTIO_BLK_T_WRITE_ZEROES, 0, &zeroes_buf, true)
            .map_err(|_| BlkError::QueueFull)?;
        self.wait_completion()?;
        let mut status_buf = [0u8; 1];
        self.queue.complete_request(&mut status_buf).map_err(|_| BlkError::IoError)?;
        Ok(())
    }

    pub(crate) fn max_sectors_per_request(&self) -> usize {
        MAX_SECTORS_PER_REQUEST
    }
}
