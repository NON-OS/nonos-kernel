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

use x86_64::PhysAddr;

use super::super::super::dma::PrpBuilder;
use super::super::super::error::NvmeError;
use super::super::super::namespace::Namespace;
use super::super::super::queue::IoQueue;
use super::super::super::security::{DmaValidator, LbaValidator};
use super::super::super::stats::NvmeStats;
use super::super::super::types::SubmissionEntry;

pub struct AsyncIoHandle {
    cid: u16,
    transfer_size: usize,
    is_write: bool,
}

impl AsyncIoHandle {
    pub fn cid(&self) -> u16 {
        self.cid
    }

    pub fn transfer_size(&self) -> usize {
        self.transfer_size
    }

    pub fn is_write(&self) -> bool {
        self.is_write
    }
}

pub fn submit_read_async(
    io_queue: &IoQueue,
    ns: &Namespace,
    start_lba: u64,
    block_count: u16,
    buffer_phys: PhysAddr,
    stats: &NvmeStats,
) -> Result<AsyncIoHandle, NvmeError> {
    LbaValidator::validate(ns, start_lba, block_count)?;

    let transfer_size = (block_count as usize) * (ns.block_size() as usize);
    DmaValidator::validate_buffer(buffer_phys, transfer_size)?;

    let prp_builder = PrpBuilder::build(buffer_phys, transfer_size)?;
    let (prp1, prp2, _prp_list) = prp_builder.into_prps();

    let cmd = SubmissionEntry::build_read(0, ns.nsid(), start_lba, block_count, prp1, prp2);

    stats.record_submit();
    let cid = io_queue.submit(cmd)?;

    Ok(AsyncIoHandle {
        cid,
        transfer_size,
        is_write: false,
    })
}

pub fn submit_write_async(
    io_queue: &IoQueue,
    ns: &Namespace,
    start_lba: u64,
    block_count: u16,
    buffer_phys: PhysAddr,
    stats: &NvmeStats,
) -> Result<AsyncIoHandle, NvmeError> {
    LbaValidator::validate(ns, start_lba, block_count)?;

    let transfer_size = (block_count as usize) * (ns.block_size() as usize);
    DmaValidator::validate_buffer(buffer_phys, transfer_size)?;

    let prp_builder = PrpBuilder::build(buffer_phys, transfer_size)?;
    let (prp1, prp2, _prp_list) = prp_builder.into_prps();

    let cmd = SubmissionEntry::build_write(0, ns.nsid(), start_lba, block_count, prp1, prp2);

    stats.record_submit();
    let cid = io_queue.submit(cmd)?;

    Ok(AsyncIoHandle {
        cid,
        transfer_size,
        is_write: true,
    })
}

pub fn wait_for_completion(
    io_queue: &IoQueue,
    handle: AsyncIoHandle,
    stats: &NvmeStats,
) -> Result<(), NvmeError> {
    let result = io_queue.wait(handle.cid);

    match result {
        Ok(_) => {
            stats.record_complete();
            if handle.is_write {
                stats.record_write(handle.transfer_size as u64);
            } else {
                stats.record_read(handle.transfer_size as u64);
            }
            Ok(())
        }
        Err(e) => {
            stats.record_error();
            Err(e)
        }
    }
}
