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

use super::super::super::error::NvmeError;
use super::super::super::queue::IoQueue;
use super::super::super::stats::NvmeStats;
use super::async_handle::AsyncIoHandle;

pub fn wait_for_completion(
    io_queue: &IoQueue,
    handle: AsyncIoHandle,
    stats: &NvmeStats,
) -> Result<(), NvmeError> {
    match io_queue.wait(handle.cid()) {
        Ok(_) => {
            stats.record_complete();
            if handle.is_write() {
                stats.record_write(handle.transfer_size() as u64);
            } else {
                stats.record_read(handle.transfer_size() as u64);
            }
            Ok(())
        }
        Err(e) => {
            stats.record_error();
            Err(e)
        }
    }
}

pub fn wait_for_completion_interrupt(
    io_queue: &IoQueue,
    handle: AsyncIoHandle,
    stats: &NvmeStats,
) -> Result<(), NvmeError> {
    match io_queue.wait_interrupt(handle.cid()) {
        Ok(_) => {
            stats.record_complete();
            if handle.is_write() {
                stats.record_write(handle.transfer_size() as u64);
            } else {
                stats.record_read(handle.transfer_size() as u64);
            }
            Ok(())
        }
        Err(e) => {
            stats.record_error();
            Err(e)
        }
    }
}
