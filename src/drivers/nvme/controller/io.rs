// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
use super::super::constants::*;
use super::super::error::NvmeError;
use super::super::types::{SubmissionEntry, DsmRange};
use super::super::dma::{DmaRegion, PrpBuilder};
use super::super::queue::IoQueue;
use super::super::namespace::Namespace;
use super::super::security::{LbaValidator, DmaValidator};
use super::super::stats::NvmeStats;

pub fn read_blocks(
    io_queue: &IoQueue,
    ns: &Namespace,
    start_lba: u64,
    block_count: u16,
    buffer_phys: PhysAddr,
    stats: &NvmeStats,
) -> Result<(), NvmeError> {
    LbaValidator::validate(ns, start_lba, block_count)?;

    let transfer_size = (block_count as usize) * (ns.block_size() as usize);
    DmaValidator::validate_buffer(buffer_phys, transfer_size)?;
    let prp_builder = PrpBuilder::build(buffer_phys, transfer_size)?;
    let (prp1, prp2, _prp_list) = prp_builder.into_prps();
    let cmd = SubmissionEntry::build_read(
        0,
        ns.nsid(),
        start_lba,
        block_count,
        prp1,
        prp2,
    );

    stats.record_submit();
    let result = io_queue.submit_and_wait(cmd);
    match result {
        Ok(_) => {
            stats.record_complete();
            stats.record_read(transfer_size as u64);
            Ok(())
        }
        Err(e) => {
            stats.record_error();
            Err(e)
        }
    }
}

pub fn write_blocks(
    io_queue: &IoQueue,
    ns: &Namespace,
    start_lba: u64,
    block_count: u16,
    buffer_phys: PhysAddr,
    stats: &NvmeStats,
) -> Result<(), NvmeError> {
    LbaValidator::validate(ns, start_lba, block_count)?;

    let transfer_size = (block_count as usize) * (ns.block_size() as usize);
    DmaValidator::validate_buffer(buffer_phys, transfer_size)?;
    let prp_builder = PrpBuilder::build(buffer_phys, transfer_size)?;
    let (prp1, prp2, _prp_list) = prp_builder.into_prps();
    let cmd = SubmissionEntry::build_write(
        0,
        ns.nsid(),
        start_lba,
        block_count,
        prp1,
        prp2,
    );

    stats.record_submit();
    let result = io_queue.submit_and_wait(cmd);

    match result {
        Ok(_) => {
            stats.record_complete();
            stats.record_write(transfer_size as u64);
            Ok(())
        }
        Err(e) => {
            stats.record_error();
            Err(e)
        }
    }
}

pub fn flush(
    io_queue: &IoQueue,
    ns: &Namespace,
    stats: &NvmeStats,
) -> Result<(), NvmeError> {
    let cmd = SubmissionEntry::build_flush(0, ns.nsid());

    stats.record_submit();
    let result = io_queue.submit_and_wait(cmd);

    match result {
        Ok(_) => {
            stats.record_complete();
            Ok(())
        }
        Err(e) => {
            stats.record_error();
            Err(e)
        }
    }
}

pub fn trim(
    io_queue: &IoQueue,
    ns: &Namespace,
    ranges: &[(u64, u32)],
    stats: &NvmeStats,
) -> Result<(), NvmeError> {
    if ranges.is_empty() || ranges.len() > DSM_MAX_RANGES {
        return Err(NvmeError::InvalidBlockCount);
    }

    for &(lba, count) in ranges {
        if count == 0 {
            return Err(NvmeError::InvalidBlockCount);
        }
        let end = lba.checked_add(count as u64).ok_or(NvmeError::LbaRangeOverflow)?;
        if end > ns.block_count() {
            return Err(NvmeError::LbaExceedsCapacity);
        }
    }

    let buffer_size = ranges.len() * DSM_RANGE_SIZE;
    let buffer = DmaRegion::allocate(buffer_size)?;
    for (i, &(lba, count)) in ranges.iter().enumerate() {
        let range = DsmRange::new(lba, count, DSM_ATTR_DEALLOCATE);
        // SAFETY: buffer is valid DMA region, pointer arithmetic within bounds
        unsafe {
            let ptr = buffer.as_mut_ptr::<DsmRange>().add(i);
            core::ptr::write_volatile(ptr, range);
        }
    }

    let cmd = SubmissionEntry::build_dsm(
        0,
        ns.nsid(),
        ranges.len() as u8,
        DSM_ATTR_DEALLOCATE,
        buffer.phys_u64(),
    );

    stats.record_submit();
    let result = io_queue.submit_and_wait(cmd);

    match result {
        Ok(_) => {
            stats.record_complete();
            Ok(())
        }
        Err(e) => {
            stats.record_error();
            Err(e)
        }
    }
}

pub fn write_zeroes(
    io_queue: &IoQueue,
    ns: &Namespace,
    start_lba: u64,
    block_count: u16,
    stats: &NvmeStats,
) -> Result<(), NvmeError> {
    LbaValidator::validate(ns, start_lba, block_count)?;

    let mut cmd = SubmissionEntry::new();
    cmd.set_opcode(IO_OPC_WRITE_ZEROES);
    cmd.nsid = ns.nsid();
    cmd.cdw10 = (start_lba & 0xFFFF_FFFF) as u32;
    cmd.cdw11 = ((start_lba >> 32) & 0xFFFF_FFFF) as u32;
    cmd.cdw12 = (block_count.saturating_sub(1) as u32) & 0xFFFF;

    stats.record_submit();
    let result = io_queue.submit_and_wait(cmd);

    match result {
        Ok(_) => {
            stats.record_complete();
            stats.record_write(ns.blocks_to_bytes(block_count as u64));
            Ok(())
        }
        Err(e) => {
            stats.record_error();
            Err(e)
        }
    }
}

pub fn compare(
    io_queue: &IoQueue,
    ns: &Namespace,
    start_lba: u64,
    block_count: u16,
    buffer_phys: PhysAddr,
    stats: &NvmeStats,
) -> Result<bool, NvmeError> {
    LbaValidator::validate(ns, start_lba, block_count)?;

    let transfer_size = (block_count as usize) * (ns.block_size() as usize);
    DmaValidator::validate_buffer(buffer_phys, transfer_size)?;

    let prp_builder = PrpBuilder::build(buffer_phys, transfer_size)?;
    let (prp1, prp2, _prp_list) = prp_builder.into_prps();

    let mut cmd = SubmissionEntry::new();
    cmd.set_opcode(IO_OPC_COMPARE);
    cmd.nsid = ns.nsid();
    cmd.prp1 = prp1;
    cmd.prp2 = prp2;
    cmd.cdw10 = (start_lba & 0xFFFF_FFFF) as u32;
    cmd.cdw11 = ((start_lba >> 32) & 0xFFFF_FFFF) as u32;
    cmd.cdw12 = (block_count.saturating_sub(1) as u32) & 0xFFFF;

    stats.record_submit();
    let result = io_queue.submit_and_wait(cmd);

    match result {
        Ok(_) => {
            stats.record_complete();
            Ok(true)
        }
        Err(NvmeError::CommandFailed { status_code }) => {
            if (status_code >> 8) == 0x02 && (status_code & 0xFF) == 0x85 {
                stats.record_complete();
                return Ok(false);
            }
            stats.record_error();
            Err(NvmeError::CommandFailed { status_code })
        }
        Err(e) => {
            stats.record_error();
            Err(e)
        }
    }
}

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
    let cmd = SubmissionEntry::build_read(
        0,
        ns.nsid(),
        start_lba,
        block_count,
        prp1,
        prp2,
    );

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
    let cmd = SubmissionEntry::build_write(
        0,
        ns.nsid(),
        start_lba,
        block_count,
        prp1,
        prp2,
    );

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
