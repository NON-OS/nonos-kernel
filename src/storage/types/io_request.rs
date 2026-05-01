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

use super::enums::{IoOperation, IoStatus};
use super::flags::IoFlags;
use super::io_result::IoCompletionCallback;
use crate::memory::addr::VirtAddr;

#[derive(Clone)]
pub struct IoRequest {
    pub operation: IoOperation,
    pub lba: u64,
    pub block_count: u32,
    pub buffer: VirtAddr,
    pub buffer_size: usize,
    pub flags: IoFlags,
    pub status: IoStatus,
    pub priority: u8,
    pub request_id: u64,
    pub timestamp: u64,
    pub completion_callback: Option<IoCompletionCallback>,
}

impl core::fmt::Debug for IoRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IoRequest")
            .field("operation", &self.operation)
            .field("lba", &self.lba)
            .field("block_count", &self.block_count)
            .field("buffer_size", &self.buffer_size)
            .field("flags", &self.flags)
            .field("status", &self.status)
            .field("priority", &self.priority)
            .field("request_id", &self.request_id)
            .finish()
    }
}

impl Default for IoRequest {
    fn default() -> Self {
        Self {
            operation: IoOperation::Read,
            lba: 0,
            block_count: 0,
            buffer: VirtAddr::zero(),
            buffer_size: 0,
            flags: IoFlags::NONE,
            status: IoStatus::Pending,
            priority: 0,
            request_id: 0,
            timestamp: 0,
            completion_callback: None,
        }
    }
}
